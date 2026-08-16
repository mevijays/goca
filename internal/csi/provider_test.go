package csi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	v1alpha1 "github.com/mevijays/goca/internal/csi/v1alpha1"
)

func TestTargetFileName(t *testing.T) {
	cases := []struct {
		name         string
		o            objectSpec
		materialized string
		want         string
		wantErr      bool
	}{
		{"kv default", objectSpec{}, "value", "value", false},
		{"kv renamed", objectSpec{FileName: "db-password"}, "value", "db-password", false},
		{"cert default names", objectSpec{}, "tls.crt", "tls.crt", false},
		{"cert renamed via items", objectSpec{Items: map[string]string{"cert": "server.pem"}}, "tls.crt", "server.pem", false},
		{"cert key renamed", objectSpec{Items: map[string]string{"key": "server-key.pem"}}, "tls.key", "server-key.pem", false},
		{"cert ca untouched when not in items", objectSpec{Items: map[string]string{"cert": "server.pem"}}, "ca.crt", "ca.crt", false},
		{"path traversal via fileName rejected", objectSpec{FileName: "../../etc/passwd"}, "value", "", true},
		{"absolute path via fileName rejected", objectSpec{FileName: "/etc/passwd"}, "value", "", true},
		{"path traversal via items rejected", objectSpec{Items: map[string]string{"cert": "../escape"}}, "tls.crt", "", true},
		{"bare dotdot rejected", objectSpec{FileName: ".."}, "value", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := targetFileName(c.o, c.materialized)
			if c.wantErr {
				if err == nil {
					t.Fatalf("targetFileName(%+v, %q) = %q, want an error", c.o, c.materialized, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("targetFileName(%+v, %q) unexpected error: %v", c.o, c.materialized, err)
			}
			if got != c.want {
				t.Errorf("targetFileName(%+v, %q) = %q, want %q", c.o, c.materialized, got, c.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	p := &Provider{RuntimeVersion: "1.2.3"}
	resp, err := p.Version(context.Background(), &v1alpha1.VersionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RuntimeName != "goca" || resp.RuntimeVersion != "1.2.3" {
		t.Errorf("Version() = %+v", resp)
	}
}

// fakeGocaServer emulates POST /api/v1/vault/fetch closely enough to drive
// Provider.Mount end to end: it checks the bearer token and returns
// per-secret results from a fixed table.
type fakeGocaServer struct {
	wantToken string
	results   map[string]fetchResult // keyed by secret name
}

func (f *fakeGocaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/vault/fetch" {
		http.NotFound(w, r)
		return
	}
	if f.wantToken != "" && r.Header.Get("Authorization") != "Bearer "+f.wantToken {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	var in fetchRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	out := fetchResponse{Identity: "system:serviceaccount:team-a:web"}
	for _, name := range in.Secrets {
		if res, ok := f.results[name]; ok {
			out.Results = append(out.Results, res)
		} else {
			out.Results = append(out.Results, fetchResult{SecretName: name, Error: "not found or not authorized"})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func mountAttributes(t *testing.T, objectsYAML, gocaAddress, audience, token string) string {
	t.Helper()
	attrs := map[string]string{
		"objects":                                objectsYAML,
		"csi.storage.k8s.io/pod.namespace":       "team-a",
		"csi.storage.k8s.io/pod.name":            "web-abc123",
		"csi.storage.k8s.io/serviceAccount.name": "web",
	}
	if gocaAddress != "" {
		attrs["gocaAddress"] = gocaAddress
	}
	if token != "" {
		tokensJSON, err := json.Marshal(map[string]tokenInfo{audience: {Token: token, ExpirationTimestamp: "2099-01-01T00:00:00Z"}})
		if err != nil {
			t.Fatal(err)
		}
		attrs["csi.storage.k8s.io/serviceAccount.tokens"] = string(tokensJSON)
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMountKVSecret(t *testing.T) {
	fake := &fakeGocaServer{
		wantToken: "pod-token",
		results: map[string]fetchResult{
			"team-a/db/password": {
				SecretName: "team-a/db/password",
				Version:    "sha256-abc",
				Files:      []fetchFile{{Name: "value", DataBase64: b64("hunter2")}},
			},
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	p := &Provider{Audience: "goca-csi"}
	objects := `
- secretName: team-a/db/password
  fileName: db-password
`
	req := &v1alpha1.MountRequest{
		Attributes: mountAttributes(t, objects, srv.URL, "goca-csi", "pod-token"),
	}
	resp, err := p.Mount(context.Background(), req)
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if len(resp.Files) != 1 {
		t.Fatalf("got %d files, want 1", len(resp.Files))
	}
	if resp.Files[0].Path != "db-password" {
		t.Errorf("file path = %q, want db-password", resp.Files[0].Path)
	}
	if string(resp.Files[0].Contents) != "hunter2" {
		t.Errorf("file contents = %q, want hunter2", resp.Files[0].Contents)
	}
	if resp.Files[0].Mode != 0o600 {
		t.Errorf("file mode = %o, want 0600", resp.Files[0].Mode)
	}
	if len(resp.ObjectVersion) != 1 || resp.ObjectVersion[0].Id != "team-a/db/password" || resp.ObjectVersion[0].Version != "sha256-abc" {
		t.Errorf("object version = %+v", resp.ObjectVersion)
	}
}

func TestMountCertificateSecretWithItemsRename(t *testing.T) {
	fake := &fakeGocaServer{
		results: map[string]fetchResult{
			"team-a/web-tls": {
				SecretName: "team-a/web-tls",
				Version:    "cert:ABCD1234",
				Files: []fetchFile{
					{Name: "tls.crt", DataBase64: b64("CERT")},
					{Name: "tls.key", DataBase64: b64("KEY")},
					{Name: "ca.crt", DataBase64: b64("CA")},
				},
			},
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	p := &Provider{Audience: "goca-csi"}
	objects := `
- secretName: team-a/web-tls
  items: { cert: server.pem, key: server-key.pem, ca: ca-bundle.pem }
`
	req := &v1alpha1.MountRequest{Attributes: mountAttributes(t, objects, srv.URL, "goca-csi", "any-token")}
	resp, err := p.Mount(context.Background(), req)
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	byPath := map[string]string{}
	for _, f := range resp.Files {
		byPath[f.Path] = string(f.Contents)
	}
	want := map[string]string{"server.pem": "CERT", "server-key.pem": "KEY", "ca-bundle.pem": "CA"}
	for path, content := range want {
		if byPath[path] != content {
			t.Errorf("file %q = %q, want %q (got files: %v)", path, byPath[path], content, byPath)
		}
	}
}

func TestMountFailsClosedOnPerSecretError(t *testing.T) {
	fake := &fakeGocaServer{
		results: map[string]fetchResult{
			"team-a/ok":   {SecretName: "team-a/ok", Version: "v1", Files: []fetchFile{{Name: "value", DataBase64: b64("x")}}},
			"team-a/nope": {SecretName: "team-a/nope", Error: "not found or not authorized"},
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	p := &Provider{Audience: "goca-csi"}
	objects := `
- secretName: team-a/ok
- secretName: team-a/nope
`
	req := &v1alpha1.MountRequest{Attributes: mountAttributes(t, objects, srv.URL, "goca-csi", "any-token")}
	if _, err := p.Mount(context.Background(), req); err == nil {
		t.Error("Mount succeeded even though one requested secret was denied - should fail closed")
	}
}

func TestMountFailsWhenFileNameUsedOnMultiFileSecret(t *testing.T) {
	fake := &fakeGocaServer{
		results: map[string]fetchResult{
			"team-a/web-tls": {
				SecretName: "team-a/web-tls",
				Version:    "cert:1",
				Files: []fetchFile{
					{Name: "tls.crt", DataBase64: b64("CERT")},
					{Name: "tls.key", DataBase64: b64("KEY")},
				},
			},
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	p := &Provider{Audience: "goca-csi"}
	// Misconfiguration: fileName instead of items on a multi-file secret.
	objects := `
- secretName: team-a/web-tls
  fileName: everything.pem
`
	req := &v1alpha1.MountRequest{Attributes: mountAttributes(t, objects, srv.URL, "goca-csi", "any-token")}
	if _, err := p.Mount(context.Background(), req); err == nil {
		t.Error("Mount silently collapsed a multi-file secret onto one fileName - should have errored")
	}
}

func TestMountRequiresAToken(t *testing.T) {
	p := &Provider{Audience: "goca-csi"}
	objects := `
- secretName: team-a/db/password
`
	// No token issued for our audience at all.
	req := &v1alpha1.MountRequest{Attributes: mountAttributes(t, objects, "http://unused.invalid", "goca-csi", "")}
	if _, err := p.Mount(context.Background(), req); err == nil {
		t.Error("Mount succeeded with no ServiceAccount token available")
	}
}

func TestMountRequiresGocaAddress(t *testing.T) {
	p := &Provider{Audience: "goca-csi"} // no DefaultGocaAddress
	objects := `
- secretName: team-a/db/password
`
	req := &v1alpha1.MountRequest{Attributes: mountAttributes(t, objects, "", "goca-csi", "pod-token")}
	if _, err := p.Mount(context.Background(), req); err == nil {
		t.Error("Mount succeeded with no gocaAddress configured anywhere")
	}
}

func TestMountUsesDefaultGocaAddress(t *testing.T) {
	fake := &fakeGocaServer{
		results: map[string]fetchResult{
			"team-a/db/password": {SecretName: "team-a/db/password", Version: "v1", Files: []fetchFile{{Name: "value", DataBase64: b64("x")}}},
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	p := &Provider{Audience: "goca-csi", DefaultGocaAddress: srv.URL}
	objects := `
- secretName: team-a/db/password
`
	// No gocaAddress in attributes - must fall back to the provider default.
	req := &v1alpha1.MountRequest{Attributes: mountAttributes(t, objects, "", "goca-csi", "pod-token")}
	if _, err := p.Mount(context.Background(), req); err != nil {
		t.Errorf("Mount did not fall back to DefaultGocaAddress: %v", err)
	}
}

func TestMountRejectsEmptyObjects(t *testing.T) {
	p := &Provider{Audience: "goca-csi", DefaultGocaAddress: "http://unused.invalid"}
	req := &v1alpha1.MountRequest{Attributes: mountAttributes(t, "[]", "", "goca-csi", "pod-token")}
	if _, err := p.Mount(context.Background(), req); err == nil {
		t.Error("Mount accepted a SecretProviderClass with no objects")
	}
}

func TestMountRejectsMalformedAttributes(t *testing.T) {
	p := &Provider{Audience: "goca-csi"}
	req := &v1alpha1.MountRequest{Attributes: "not json"}
	if _, err := p.Mount(context.Background(), req); err == nil {
		t.Error("Mount accepted malformed attributes JSON")
	}
}
