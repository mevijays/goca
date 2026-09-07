// Package k8sauth validates the Kubernetes ServiceAccount tokens presented
// by the Secrets Store CSI Driver on behalf of a requesting pod, and extracts
// the caller's identity (namespace, ServiceAccount, pod). It is the
// authentication layer for internal/csi's provider - the CSI-facing REST
// endpoint trusts whatever identity a Verifier returns, so getting this
// right is the entire trust boundary between "any pod" and "a pod bound to
// this secret" (see internal/vault.MatchesBinding for the authorization side).
package k8sauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Identity is a verified ServiceAccount token's claims - who is asking, from
// goca's point of view. PodName/PodUID are populated only for bound tokens
// minted via the TokenRequest API (which is what a CSI SecretProviderClass's
// tokenRequests always produces); a long-lived ServiceAccount token Secret
// carries no pod information and leaves them empty.
//
// AuthMethod is the name of the CSI trust domain (k8s_auth_methods row) whose
// Verifier validated this token. It is set by the caller that performed the
// lookup - the Verifier itself does not know its own name - and is the axis a
// binding uses to scope itself to a particular cluster. A token from cluster A
// and a token from cluster B can carry the same (Namespace, ServiceAccount);
// AuthMethod is what tells them apart.
type Identity struct {
	Namespace      string
	ServiceAccount string
	PodName        string
	PodUID         string
	AuthMethod     string
}

// String renders the identity the way Kubernetes itself does, for logging
// and audit records.
func (id Identity) String() string {
	return fmt.Sprintf("system:serviceaccount:%s:%s", id.Namespace, id.ServiceAccount)
}

// Config configures a Verifier. At least one of IssuerURL or the TokenReview
// fields must be set.
type Config struct {
	// IssuerURL is the cluster's ServiceAccount OIDC issuer
	// (--service-account-issuer on the API server, or a managed cluster's
	// published issuer such as an EKS/GKE/AKS OIDC provider URL). When set
	// and reachable, tokens are verified locally against its JWKS - no
	// per-request round trip to the API server.
	IssuerURL string
	// Audience every token must be bound to - normally this provider's own
	// name, matching the SecretProviderClass's tokenRequests[].audience.
	// Required.
	Audience string
	// InsecureSkipVerify skips TLS verification when reaching IssuerURL.
	// Only ever appropriate against a lab cluster with a self-signed issuer.
	InsecureSkipVerify bool

	// APIServerURL, CACertPEM and ReviewerToken configure the TokenReview
	// API fallback, used whenever IssuerURL is empty or its discovery
	// document is unreachable - the common case for kind and many on-prem
	// clusters, whose default issuer (https://kubernetes.default.svc...) is
	// not publicly resolvable. ReviewerToken must belong to a
	// ServiceAccount bound to the system:auth-delegator ClusterRole.
	APIServerURL  string
	CACertPEM     []byte
	ReviewerToken string
}

func (c Config) tokenReviewConfigured() bool {
	return c.APIServerURL != "" && c.ReviewerToken != ""
}

// InClusterConfig builds a Config from the standard environment a pod runs
// in: its own projected ServiceAccount token and CA bundle (for the
// TokenReview fallback) and $KUBERNETES_SERVICE_HOST/PORT for the API server
// address. issuerURL is tried first when non-empty; pass "" to rely on
// TokenReview alone.
func InClusterConfig(issuerURL, audience string) (Config, error) {
	const (
		tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	)
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Config{}, errors.New("k8sauth: KUBERNETES_SERVICE_HOST/PORT are not set - not running in a pod")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return Config{}, fmt.Errorf("k8sauth: read in-cluster token: %w", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return Config{}, fmt.Errorf("k8sauth: read in-cluster CA bundle: %w", err)
	}
	return Config{
		IssuerURL:     issuerURL,
		Audience:      audience,
		APIServerURL:  "https://" + net.JoinHostPort(host, port),
		CACertPEM:     ca,
		ReviewerToken: strings.TrimSpace(string(token)),
	}, nil
}

// Verifier validates a Kubernetes projected/bound ServiceAccount token and
// extracts the caller's identity. It prefers local JWKS-based verification
// (cheap, no per-call round trip to the API server) and falls back to the
// TokenReview API when OIDC discovery is not configured or not reachable.
type Verifier struct {
	cfg        Config
	httpClient *http.Client

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
	oidcErr  error // last discovery failure; retried lazily on the next Verify

	reviewClient *http.Client
}

// New builds a Verifier. OIDC discovery (if IssuerURL is set) happens lazily
// on first use, mirroring internal/oidcauth, so an unreachable issuer at
// startup never blocks `goca run csi-provider` - only an actual Mount
// request does, and that falls back to TokenReview when configured.
func New(cfg Config) (*Verifier, error) {
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("k8sauth: an audience is required")
	}
	if cfg.IssuerURL == "" && !cfg.tokenReviewConfigured() {
		return nil, errors.New("k8sauth: configure an issuer URL, a TokenReview API server, or both")
	}
	v := &Verifier{cfg: cfg, httpClient: http.DefaultClient}
	if cfg.InsecureSkipVerify {
		v.httpClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // opt-in, lab use only
		}
	}
	if cfg.tokenReviewConfigured() {
		var pool *x509.CertPool
		if len(cfg.CACertPEM) > 0 {
			pool = x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
				return nil, errors.New("k8sauth: no certificates found in the supplied CA bundle")
			}
		}
		tlsCfg := &tls.Config{RootCAs: pool} //nolint:gosec // pool nil = system roots, both valid trust configurations
		if cfg.InsecureSkipVerify {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // opt-in, lab use only
		}
		v.reviewClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	}
	return v, nil
}

// ready reports whether OIDC-based verification is usable, discovering the
// issuer on first call and retrying discovery on every call while it keeps
// failing - a provider that was briefly unreachable self-heals on the next
// Verify instead of staying broken until the process restarts.
func (v *Verifier) ready(ctx context.Context) bool {
	if v.cfg.IssuerURL == "" {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return true
	}
	dctx := oidc.ClientContext(ctx, v.httpClient)
	provider, err := oidc.NewProvider(dctx, v.cfg.IssuerURL)
	if err != nil {
		v.oidcErr = fmt.Errorf("discover issuer %s: %w", v.cfg.IssuerURL, err)
		return false
	}
	v.verifier = provider.Verifier(&oidc.Config{ClientID: v.cfg.Audience})
	v.oidcErr = nil
	return true
}

// Verify validates token and returns the caller's identity. Whichever
// mechanism is used, the token must be bound to the Verifier's configured
// audience - this is what stops a token minted for some other purpose (or
// with no audience restriction at all) from being replayed against the
// vault.
func (v *Verifier) Verify(ctx context.Context, token string) (*Identity, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("k8sauth: empty token")
	}
	if v.ready(ctx) {
		return v.verifyOIDC(ctx, token)
	}
	if v.cfg.tokenReviewConfigured() {
		return v.verifyTokenReview(ctx, token)
	}
	return nil, fmt.Errorf("k8sauth: OIDC issuer unreachable and no TokenReview fallback is configured: %w", v.oidcErr)
}

//
// ---------- OIDC / JWKS path ----------
//

// k8sTokenClaims is the shape of a Kubernetes bound ServiceAccount token
// (TokenRequest API, GA since 1.21). The "kubernetes.io" claim carries
// structured pod/ServiceAccount identity; "sub" is the fallback every
// ServiceAccount token (bound or not) carries.
type k8sTokenClaims struct {
	Sub        string `json:"sub"`
	Kubernetes struct {
		Namespace string `json:"namespace"`
		Pod       struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

func (v *Verifier) verifyOIDC(ctx context.Context, token string) (*Identity, error) {
	dctx := oidc.ClientContext(ctx, v.httpClient)
	idToken, err := v.verifier.Verify(dctx, token)
	if err != nil {
		return nil, fmt.Errorf("k8sauth: verify token: %w", err)
	}
	var claims k8sTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("k8sauth: decode token claims: %w", err)
	}
	if claims.Kubernetes.Namespace != "" && claims.Kubernetes.ServiceAccount.Name != "" {
		return &Identity{
			Namespace:      claims.Kubernetes.Namespace,
			ServiceAccount: claims.Kubernetes.ServiceAccount.Name,
			PodName:        claims.Kubernetes.Pod.Name,
			PodUID:         claims.Kubernetes.Pod.UID,
		}, nil
	}
	ns, sa, ok := parseServiceAccountSubject(claims.Sub)
	if !ok {
		return nil, fmt.Errorf("k8sauth: token has neither a kubernetes.io claim nor a recognizable ServiceAccount subject: %q", claims.Sub)
	}
	return &Identity{Namespace: ns, ServiceAccount: sa}, nil
}

// parseServiceAccountSubject splits the standard
// "system:serviceaccount:<namespace>:<name>" subject/username format
// Kubernetes uses for every ServiceAccount identity, bound token or not.
func parseServiceAccountSubject(sub string) (namespace, name string, ok bool) {
	parts := strings.Split(sub, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

//
// ---------- TokenReview fallback ----------
//

type tokenReviewRequest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences,omitempty"`
	} `json:"spec"`
}

type tokenReviewResponse struct {
	Status struct {
		Authenticated bool   `json:"authenticated"`
		Error         string `json:"error"`
		User          struct {
			Username string              `json:"username"`
			UID      string              `json:"uid"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
	} `json:"status"`
}

// The extra keys the API server populates for a bound ServiceAccount token
// authenticated via TokenReview - see
// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens.
const (
	extraPodName = "authentication.kubernetes.io/pod-name"
	extraPodUID  = "authentication.kubernetes.io/pod-uid"
)

func (v *Verifier) verifyTokenReview(ctx context.Context, token string) (*Identity, error) {
	body := tokenReviewRequest{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
	body.Spec.Token = token
	body.Spec.Audiences = []string{v.cfg.Audience}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(v.cfg.APIServerURL, "/") + "/apis/authentication.k8s.io/v1/tokenreviews"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+v.cfg.ReviewerToken)

	resp, err := v.reviewClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8sauth: TokenReview request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("k8sauth: TokenReview returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	var out tokenReviewResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("k8sauth: decode TokenReview response: %w", err)
	}
	if !out.Status.Authenticated {
		msg := out.Status.Error
		if msg == "" {
			msg = "token rejected"
		}
		return nil, fmt.Errorf("k8sauth: %s", msg)
	}
	ns, sa, ok := parseServiceAccountSubject(out.Status.User.Username)
	if !ok {
		return nil, fmt.Errorf("k8sauth: TokenReview authenticated a non-ServiceAccount identity %q", out.Status.User.Username)
	}
	id := &Identity{Namespace: ns, ServiceAccount: sa}
	if extra := out.Status.User.Extra[extraPodName]; len(extra) > 0 {
		id.PodName = extra[0]
	}
	if extra := out.Status.User.Extra[extraPodUID]; len(extra) > 0 {
		id.PodUID = extra[0]
	}
	return id, nil
}
