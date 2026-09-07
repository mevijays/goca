/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package goca

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// fakeTokenRequest installs a reactor answering every TokenRequest with a
// fixed token, and returns a channel of the requests it saw - tests read
// from it to assert the right audience/ServiceAccount/namespace was asked
// for, without needing a real Kubernetes API server.
func fakeTokenRequest(t *testing.T, token string) (*fake.Clientset, chan *authenticationv1.TokenRequest) {
	t.Helper()
	cs := fake.NewSimpleClientset()
	seen := make(chan *authenticationv1.TokenRequest, 8)
	cs.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "token" {
			return false, nil, nil
		}
		ca, ok := action.(k8stesting.CreateAction)
		if !ok {
			return false, nil, nil
		}
		tr, ok := ca.GetObject().(*authenticationv1.TokenRequest)
		if !ok {
			return false, nil, nil
		}
		seen <- tr.DeepCopy()
		out := tr.DeepCopy()
		out.Status.Token = token
		return true, out, nil
	})
	return cs, seen
}

func testClient(t *testing.T, server string, cs *fake.Clientset) *Client {
	t.Helper()
	return &Client{
		corev1:      cs.CoreV1(),
		http:        http.DefaultClient,
		server:      server,
		audience:    "goca-csi",
		authMethod:  "test-cluster",
		saName:      "eso-reader",
		saNamespace: "team-a",
	}
}

func fakeStore(provider *esv1.GocaProvider) *esv1.SecretStore {
	return &esv1.SecretStore{
		ObjectMeta: metav1.ObjectMeta{Name: "goca", Namespace: "team-a"},
		Spec:       esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{Goca: provider}},
	}
}

func fakeSA(name string) esmeta.ServiceAccountSelector {
	return esmeta.ServiceAccountSelector{Name: name}
}

// TestGetSecretMintsATokenAndFetches is the core happy path: a fresh token
// is requested for the configured ServiceAccount, with the configured
// audience, and used to fetch the secret.
func TestGetSecretMintsATokenAndFetches(t *testing.T) {
	var gotAuth, gotAuthMethod, gotKey, gotProperty string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAuthMethod = r.Header.Get("X-Goca-Auth-Method")
		gotKey = r.URL.Query().Get("key")
		gotProperty = r.URL.Query().Get("property")
		_ = json.NewEncoder(w).Encode(esoSecretResponse{
			Name: gotKey, Property: "value",
			ValueBase64: base64.StdEncoding.EncodeToString([]byte("s3cr3t")),
		})
	}))
	defer srv.Close()

	cs, seen := fakeTokenRequest(t, "minted-token")
	c := testClient(t, srv.URL, cs)

	got, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "team-a/db-password"})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("value = %q, want s3cr3t", got)
	}
	if gotAuth != "Bearer minted-token" {
		t.Fatalf("Authorization = %q, want the minted token", gotAuth)
	}
	if gotAuthMethod != "test-cluster" {
		t.Fatalf("X-Goca-Auth-Method = %q, want test-cluster", gotAuthMethod)
	}
	if gotKey != "team-a/db-password" {
		t.Fatalf("key = %q", gotKey)
	}
	if gotProperty != "" {
		t.Fatalf("property = %q, want empty for a single-file secret", gotProperty)
	}

	select {
	case tr := <-seen:
		if len(tr.Spec.Audiences) != 1 || tr.Spec.Audiences[0] != "goca-csi" {
			t.Fatalf("requested audiences = %v, want [goca-csi]", tr.Spec.Audiences)
		}
		if tr.Spec.ExpirationSeconds == nil || *tr.Spec.ExpirationSeconds != tokenExpirationSeconds {
			t.Fatalf("ExpirationSeconds = %v, want %d", tr.Spec.ExpirationSeconds, tokenExpirationSeconds)
		}
	default:
		t.Fatal("no TokenRequest was made")
	}
}

// TestGetSecretPropertySelectsAFile confirms ref.Property becomes ?property=.
func TestGetSecretPropertySelectsAFile(t *testing.T) {
	var gotProperty string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProperty = r.URL.Query().Get("property")
		_ = json.NewEncoder(w).Encode(esoSecretResponse{
			ValueBase64: base64.StdEncoding.EncodeToString([]byte("PEM-DATA")),
		})
	}))
	defer srv.Close()

	cs, _ := fakeTokenRequest(t, "tok")
	c := testClient(t, srv.URL, cs)

	got, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "team-a/tls", Property: "tls.crt"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "PEM-DATA" {
		t.Fatalf("value = %q", got)
	}
	if gotProperty != "tls.crt" {
		t.Fatalf("property sent = %q, want tls.crt", gotProperty)
	}
}

// TestGetSecretMapFetchesAllFiles confirms an empty Property triggers
// ?all=true and every returned file is base64-decoded correctly.
func TestGetSecretMapFetchesAllFiles(t *testing.T) {
	var gotAll string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAll = r.URL.Query().Get("all")
		_ = json.NewEncoder(w).Encode(esoSecretResponse{
			Name: "team-a/tls",
			Files: map[string]string{
				"tls.crt": base64.StdEncoding.EncodeToString([]byte("CERT")),
				"tls.key": base64.StdEncoding.EncodeToString([]byte("KEY")),
				"ca.crt":  base64.StdEncoding.EncodeToString([]byte("CA")),
			},
		})
	}))
	defer srv.Close()

	cs, _ := fakeTokenRequest(t, "tok")
	c := testClient(t, srv.URL, cs)

	got, err := c.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "team-a/tls"})
	if err != nil {
		t.Fatal(err)
	}
	if gotAll != "true" {
		t.Fatalf("all param = %q, want true", gotAll)
	}
	want := map[string]string{"tls.crt": "CERT", "tls.key": "KEY", "ca.crt": "CA"}
	for k, v := range want {
		if string(got[k]) != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d", len(got), len(want))
	}
}

// TestGetSecretMapWithPropertyFetchesOne confirms a non-empty Property on
// GetSecretMap fetches just that one file rather than everything.
func TestGetSecretMapWithPropertyFetchesOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("all") == "true" {
			t.Error("GetSecretMap with a property set should not request all=true")
		}
		_ = json.NewEncoder(w).Encode(esoSecretResponse{ValueBase64: base64.StdEncoding.EncodeToString([]byte("CERT"))})
	}))
	defer srv.Close()

	cs, _ := fakeTokenRequest(t, "tok")
	c := testClient(t, srv.URL, cs)

	got, err := c.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "team-a/tls", Property: "tls.crt"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got["tls.crt"]) != "CERT" {
		t.Fatalf("got = %v", got)
	}
}

// TestGetSecretNotFoundMapsToNoSecretErr confirms a 404 (goca's identical
// response for "does not exist" and "not bound to this identity") maps to
// ESO's sentinel error so deletionPolicy behaves correctly.
func TestGetSecretNotFoundMapsToNoSecretErr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found or not authorized"})
	}))
	defer srv.Close()

	cs, _ := fakeTokenRequest(t, "tok")
	c := testClient(t, srv.URL, cs)

	_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "nope"})
	if !errors.Is(err, esv1.NoSecretErr) {
		t.Fatalf("err = %v, want esv1.NoSecretErr", err)
	}
}

// TestGetSecretServerErrorSurfacesGocaMessage confirms a non-404 error
// includes goca's own error text, not just the HTTP status.
func TestGetSecretServerErrorSurfacesGocaMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": `secret "x" has 3 parts; add ?property=`})
	}))
	defer srv.Close()

	cs, _ := fakeTokenRequest(t, "tok")
	c := testClient(t, srv.URL, cs)

	_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "x"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); !strings.Contains(got, "has 3 parts") {
		t.Fatalf("error = %q, want it to include goca's own message", got)
	}
}

// TestWriteOperationsAreRefused confirms the read-only capability
// declaration is backed by every write method actually refusing.
func TestWriteOperationsAreRefused(t *testing.T) {
	cs, _ := fakeTokenRequest(t, "tok")
	c := testClient(t, "http://unused.invalid", cs)

	if err := c.PushSecret(context.Background(), nil, nil); err == nil {
		t.Error("PushSecret should be refused")
	}
	if err := c.DeleteSecret(context.Background(), nil); err == nil {
		t.Error("DeleteSecret should be refused")
	}
	if ok, err := c.SecretExists(context.Background(), nil); ok || err == nil {
		t.Error("SecretExists should be refused")
	}
	if _, err := c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{}); err == nil {
		t.Error("GetAllSecrets should be refused")
	}
	if got := (&Provider{}).Capabilities(); got != esv1.SecretStoreReadOnly {
		t.Fatalf("Capabilities = %v, want ReadOnly", got)
	}
}

// TestValidateStoreRejectsIncompleteConfig covers the fields ValidateStore
// actually enforces.
func TestValidateStoreRejectsIncompleteConfig(t *testing.T) {
	p := &Provider{}
	cases := []struct {
		name  string
		store *esv1.SecretStore
	}{
		{"no server", fakeStore(&esv1.GocaProvider{ServiceAccountRef: fakeSA("eso-reader")})},
		{"no serviceAccountRef", fakeStore(&esv1.GocaProvider{Server: "https://goca.example.com"})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := p.ValidateStore(c.store); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	valid := fakeStore(&esv1.GocaProvider{Server: "https://goca.example.com", ServiceAccountRef: fakeSA("eso-reader")})
	if _, err := p.ValidateStore(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}
