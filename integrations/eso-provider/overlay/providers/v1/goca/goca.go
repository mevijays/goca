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

// Package goca implements the External Secrets provider for goca
// (https://github.com/mevijays/goca), a self-hosted certificate authority
// with a built-in secret manager.
//
// Authentication mints a fresh, short-lived Kubernetes ServiceAccount token
// via the TokenRequest API on every fetch - see NewClient's comment for why
// controller-runtime's client can't do this and a separate client-go
// clientset is built instead, mirroring how the Akeyless provider's
// ServiceAccountRef auth mode already does exactly this in this same
// repository. goca verifies the minted token via TokenReview, the same way
// it verifies its CSI provider's per-pod tokens, and authorizes it against
// the secret's own bindings - this provider carries no goca credential of
// its own and is read-only, matching how the CSI path works.
package goca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlcfg "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
)

// tokenExpirationSeconds is short deliberately - this token exists only for
// the duration of one fetch, never stored, so there is nothing to gain from
// a longer lifetime and every reason to keep the blast radius of a leaked
// one small.
const tokenExpirationSeconds = 600

// Provider satisfies esv1.Provider.
type Provider struct{}

var (
	_ esv1.Provider      = &Provider{}
	_ esv1.SecretsClient = &Client{}
)

// Capabilities reports read-only: goca's workload-facing endpoint has no
// write path by design (writes go through its admin-authenticated API,
// never through a ServiceAccount-token-verified one), so PushSecret always
// fails - declaring ReadOnly here, rather than ReadWrite, means ESO can say
// so at validation time instead of only on the first failed PushSecret.
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
}

// ValidateStore checks the provider config is structurally sound. It does
// not reach goca or Kubernetes - NewClient does that, at first use.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	spec, err := getProvider(store)
	if err != nil {
		return nil, err
	}
	if spec.Server == "" {
		return nil, errors.New("goca: server is required")
	}
	if _, err := url.Parse(spec.Server); err != nil {
		return nil, fmt.Errorf("goca: server is not a valid URL: %w", err)
	}
	if spec.ServiceAccountRef.Name == "" {
		return nil, errors.New("goca: serviceAccountRef.name is required")
	}
	return nil, nil
}

// NewClient builds a Client. It constructs its own client-go clientset in
// addition to the controller-runtime one ESO hands it, because
// controller-runtime's client does not support the TokenRequest subresource
// API this provider needs to mint a ServiceAccount token - the Akeyless
// provider's ServiceAccountRef auth mode (providers/v1/akeyless) does the
// same thing, for the same reason.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube client.Client, namespace string) (esv1.SecretsClient, error) {
	spec, err := getProvider(store)
	if err != nil {
		return nil, err
	}

	restCfg, err := ctrlcfg.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("goca: build Kubernetes REST config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("goca: build Kubernetes clientset: %w", err)
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	if len(spec.CABundle) > 0 || spec.CAProvider != nil {
		ca, err := esutils.FetchCACertFromSource(ctx, esutils.CreateCertOpts{
			CABundle:   spec.CABundle,
			CAProvider: spec.CAProvider,
			StoreKind:  store.GetObjectKind().GroupVersionKind().Kind,
			Namespace:  namespace,
			Client:     kube,
		})
		if err != nil {
			return nil, fmt.Errorf("goca: load CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(ca); !ok {
			return nil, errors.New("goca: caBundle/caProvider did not contain a usable certificate")
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}}
	}

	saNamespace := namespace
	if store.GetObjectKind().GroupVersionKind().Kind == esv1.ClusterSecretStoreKind && spec.ServiceAccountRef.Namespace != nil {
		saNamespace = *spec.ServiceAccountRef.Namespace
	}

	audience := spec.Audience
	if audience == "" {
		audience = "goca-csi"
	}

	return &Client{
		corev1:      clientset.CoreV1(),
		http:        httpClient,
		server:      strings.TrimRight(spec.Server, "/"),
		audience:    audience,
		authMethod:  spec.AuthMethod,
		saName:      spec.ServiceAccountRef.Name,
		saNamespace: saNamespace,
	}, nil
}

// Client implements esv1.SecretsClient against one goca server, minting its
// own bearer token per request.
type Client struct {
	corev1      typedcorev1.CoreV1Interface
	http        *http.Client
	server      string
	audience    string
	authMethod  string
	saName      string
	saNamespace string
}

// token mints a fresh, audience-bound token for the configured
// ServiceAccount via the Kubernetes TokenRequest API - the same mechanism
// kubelet uses internally for projected volumes, just invoked directly
// rather than mounted. Nothing is cached: a fetch that is seconds apart from
// the last one still mints a new token, trading a small amount of API
// server load for never holding a token longer than it takes to use it.
func (c *Client) token(ctx context.Context) (string, error) {
	exp := int64(tokenExpirationSeconds)
	tr, err := c.corev1.ServiceAccounts(c.saNamespace).CreateToken(ctx, c.saName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{c.audience},
			ExpirationSeconds: &exp,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("goca: request a token for ServiceAccount %s/%s: %w", c.saNamespace, c.saName, err)
	}
	return tr.Status.Token, nil
}

type esoSecretResponse struct {
	Name        string `json:"name"`
	Property    string `json:"property"`
	Version     string `json:"version"`
	Value       string `json:"value"`
	ValueBase64 string `json:"value_base64"`
	// Files is only present when the request set all=true: every part of a
	// multi-file secret, keyed by file name, each value base64-encoded the
	// same way ValueBase64 is for a single fetch.
	Files map[string]string `json:"files,omitempty"`
}

// fetch calls GET /api/v1/eso/secret?key=...&property=...[&all=true] - see
// docs/eso.md and internal/web/api_eso.go in the goca repository for the
// full contract. all=true is GetSecretMap's path: it returns every file a
// multi-file secret has (Files) instead of requiring one to be named.
func (c *Client) fetch(ctx context.Context, key, property string, all bool) (*esoSecretResponse, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}

	q := url.Values{"key": {key}}
	if property != "" {
		q.Set("property", property)
	}
	if all {
		q.Set("all", "true")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+"/api/v1/eso/secret?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if c.authMethod != "" {
		req.Header.Set("X-Goca-Auth-Method", c.authMethod)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("goca: request %s: %w", key, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("goca: read response for %s: %w", key, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// goca returns 404 identically for "does not exist" and "exists but
		// not bound to this identity" - see errNotFoundOrNotAuthorized in
		// api_vault_fetch.go. Either way, from ESO's side, the secret is not
		// there: this maps to esv1.NoSecretErr so deletionPolicy applies.
		return nil, esv1.NoSecretErr
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &apiErr)
		msg := apiErr.Error
		if msg == "" {
			msg = string(body)
		}
		return nil, fmt.Errorf("goca: %s: HTTP %d: %s", key, resp.StatusCode, msg)
	}

	var out esoSecretResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("goca: decode response for %s: %w", key, err)
	}
	return &out, nil
}

// GetSecret returns one property (or the only file, for a single-file
// secret) as raw bytes, decoded from value_base64 - authoritative and
// correct for both text and binary content, unlike the value field (present
// only for valid UTF-8) that exists in the wire format for the generic
// Webhook provider's JSONPath extraction.
func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	res, err := c.fetch(ctx, ref.Key, ref.Property, false)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(res.ValueBase64)
	if err != nil {
		return nil, fmt.Errorf("goca: decode value_base64 for %s: %w", ref.Key, err)
	}
	return data, nil
}

// GetSecretMap returns every property of a secret as a map - the one thing
// GetSecret can't do (it takes exactly one property), and the natural fit
// for a multi-file secret (a certificate's tls.crt/tls.key/ca.crt) synced in
// one ExternalSecret data entry via dataFrom rather than three.
func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	if ref.Property != "" {
		v, err := c.GetSecret(ctx, ref)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{ref.Property: v}, nil
	}
	res, err := c.fetch(ctx, ref.Key, "", true)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(res.Files))
	for name, b64 := range res.Files {
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("goca: decode %s/%s: %w", ref.Key, name, err)
		}
		out[name] = data
	}
	return out, nil
}

// GetAllSecrets is not supported: goca has no "list secrets matching a name
// pattern" concept exposed to a workload identity, by design - the caller
// must know which secret it is bound to.
func (c *Client) GetAllSecrets(_ context.Context, _ esv1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, errors.New("goca: GetAllSecrets is not supported - this provider is read-only and secrets must be named explicitly")
}

// PushSecret, DeleteSecret and SecretExists are all refused: see
// Provider.Capabilities.
func (c *Client) PushSecret(_ context.Context, _ *corev1.Secret, _ esv1.PushSecretData) error {
	return errors.New("goca: PushSecret is not supported - this provider is read-only")
}

func (c *Client) DeleteSecret(_ context.Context, _ esv1.PushSecretRemoteRef) error {
	return errors.New("goca: DeleteSecret is not supported - this provider is read-only")
}

func (c *Client) SecretExists(_ context.Context, _ esv1.PushSecretRemoteRef) (bool, error) {
	return false, errors.New("goca: SecretExists is not supported - this provider is read-only")
}

// Validate confirms goca is reachable. It does not mint a token or make an
// authenticated request - a misconfigured ServiceAccountRef or a binding
// that does not yet exist both surface on the first real fetch instead, the
// same way the CSI provider only discovers a bad binding on Mount.
func (c *Client) Validate() (esv1.ValidationResult, error) {
	if err := esutils.NetworkValidate(c.server, 15*time.Second); err != nil {
		return esv1.ValidationResultError, err
	}
	return esv1.ValidationResultReady, nil
}

func (c *Client) Close(_ context.Context) error { return nil }

func getProvider(store esv1.GenericStore) (*esv1.GocaProvider, error) {
	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.Goca == nil {
		return nil, errors.New("goca: no goca provider config found in this SecretStore")
	}
	return spec.Provider.Goca, nil
}

// NewProvider creates a new Provider instance.
func NewProvider() esv1.Provider { return &Provider{} }

// ProviderSpec returns the provider specification for registration.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{Goca: &esv1.GocaProvider{}}
}

// MaintenanceStatus returns the maintenance status of the provider.
func MaintenanceStatus() esv1.MaintenanceStatus { return esv1.MaintenanceStatusMaintained }
