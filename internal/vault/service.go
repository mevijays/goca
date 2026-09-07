// Package vault is goca's secret manager: named, versioned secrets sealed
// with internal/pqcrypt's hybrid ML-KEM-768 + X25519 envelope, exposed to
// the CLI, the REST API and (in a later phase) a Kubernetes Secrets Store
// CSI Driver provider. See docs/secrets.md for the design and threat model.
package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/metrics"
	"github.com/mevijays/goca/internal/pqcrypt"
	"github.com/mevijays/goca/internal/store"
)

// aadPrefix namespaces the AAD goca binds every sealed payload to, so a
// ciphertext from some other pqcrypt user in this binary (there are none
// today) could never be confused for a vault secret version.
const aadPrefix = "goca/secret/v1"

// Service coordinates the secret manager: the database, the pqcrypt vault
// keypair, and (for certificate-type secrets) the CA service that actually
// holds the certificate and its private key.
type Service struct {
	st    *store.Store
	vault *pqcrypt.Vault
	ca    *ca.Service // nil is tolerated; only certificate-type operations need it
}

// New derives the vault keypair from the config's master key - the same key
// that already protects CA private keys and LDAP/OIDC secrets, so restarts
// stay unattended and "back up config.yaml with the database" keeps being
// the whole story (see docs/secrets.md for the key-custody trade-off this makes).
// caSvc may be nil in a context that never touches certificate-type secrets;
// every certificate-type operation reports a clear error in that case
// instead of a nil-pointer panic.
func New(cfg *config.Config, st *store.Store, caSvc *ca.Service) (*Service, error) {
	key, err := cfg.MasterKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	v, err := pqcrypt.DeriveVault(key)
	if err != nil {
		return nil, fmt.Errorf("derive vault keypair: %w", err)
	}
	return &Service{st: st, vault: v, ca: caSvc}, nil
}

// Store exposes the underlying store for admin operations.
func (s *Service) Store() *store.Store { return s.st }

func aad(secretID int64, version int) []byte {
	return []byte(fmt.Sprintf("%s|%d|%d", aadPrefix, secretID, version))
}

// File is one file a secret materializes into - what a "goca secret get"
// writes to disk, and what a later CSI provider phase writes into a pod's
// volume.
type File struct {
	Name string
	Data []byte
}

//
// ---------- secret metadata ----------
//

// CreateInput describes a new secret. It carries no payload: for kv/file
// secrets, call Put next; a certificate secret is complete on creation,
// since its content always comes from the linked certificate.
type CreateInput struct {
	Name         string            `json:"name"`
	Type         string            `json:"type"` // kv | file | certificate; defaults to kv
	Description  string            `json:"description"`
	Labels       map[string]string `json:"labels"`
	RotationDays int               `json:"rotation_days"`
	CertID       *int64            `json:"cert_id,omitempty"` // required, and only meaningful, when Type == certificate
	Actor        string            `json:"-"`
}

// Create registers a new secret's metadata.
func (s *Service) Create(ctx context.Context, in CreateInput) (*store.Secret, error) {
	name := normalizeName(in.Name)
	if name == "" {
		return nil, errors.New("a secret name is required")
	}
	typ := in.Type
	if typ == "" {
		typ = store.SecretTypeKV
	}
	switch typ {
	case store.SecretTypeKV, store.SecretTypeFile:
		if in.CertID != nil {
			return nil, fmt.Errorf("cert_id is only valid for %s secrets", store.SecretTypeCertificate)
		}
	case store.SecretTypeCertificate:
		if in.CertID == nil {
			return nil, errors.New("a certificate secret requires cert_id")
		}
		if s.ca == nil {
			return nil, errors.New("certificate secrets are unavailable: no CA service is configured")
		}
		if _, err := s.ca.GetCertificate(ctx, *in.CertID); err != nil {
			return nil, fmt.Errorf("resolve certificate %d: %w", *in.CertID, err)
		}
	default:
		return nil, fmt.Errorf("unknown secret type %q (want kv, file or certificate)", typ)
	}

	sec, err := s.st.CreateSecret(ctx, &store.Secret{
		Name:         name,
		Type:         typ,
		Description:  in.Description,
		LabelsJSON:   store.EncodeLabels(in.Labels),
		CertID:       in.CertID,
		RotationDays: in.RotationDays,
		CreatedBy:    in.Actor,
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, in.Actor, "secret.create", name, "type="+typ)
	metrics.SecretCreatedTotal.WithLabelValues(typ).Inc()
	return sec, nil
}

// Get resolves a secret by name.
func (s *Service) Get(ctx context.Context, name string) (*store.Secret, error) {
	return s.st.GetSecretByName(ctx, normalizeName(name))
}

// GetByID resolves a secret by its numeric id - what the REST API addresses
// secrets by, mirroring how CAs and certificates are addressed there. The
// CLI and every other Service method address secrets by name instead, since
// that is what an operator or a SecretProviderClass actually types.
func (s *Service) GetByID(ctx context.Context, id int64) (*store.Secret, error) {
	return s.st.GetSecret(ctx, id)
}

// List returns every secret, optionally narrowed to one type.
func (s *Service) List(ctx context.Context, typ string) ([]*store.Secret, error) {
	return s.st.ListSecrets(ctx, typ)
}

// UpdateMeta changes a secret's description, labels and rotation policy.
func (s *Service) UpdateMeta(ctx context.Context, name, description string, labels map[string]string, rotationDays int, actor string) (*store.Secret, error) {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return nil, err
	}
	if err := s.st.UpdateSecretMeta(ctx, sec.ID, description, store.EncodeLabels(labels), rotationDays); err != nil {
		return nil, err
	}
	s.audit(ctx, actor, "secret.update", sec.Name, "")
	return s.st.GetSecret(ctx, sec.ID)
}

// SetDisabled enables or disables a secret without destroying any version.
// A disabled secret is refused by Get, GetLatest and (in a later phase) the
// CSI provider.
func (s *Service) SetDisabled(ctx context.Context, name string, disabled bool, actor string) error {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return err
	}
	if err := s.st.SetSecretDisabled(ctx, sec.ID, disabled); err != nil {
		return err
	}
	action := "secret.enable"
	if disabled {
		action = "secret.disable"
	}
	s.audit(ctx, actor, action, sec.Name, "")
	return nil
}

// Delete removes a secret, every version, and every binding permanently.
func (s *Service) Delete(ctx context.Context, name, actor string) error {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return err
	}
	if err := s.st.DeleteSecret(ctx, sec.ID); err != nil {
		return err
	}
	s.audit(ctx, actor, "secret.delete", sec.Name, fmt.Sprintf("type=%s versions=%d", sec.Type, sec.CurrentVersion))
	metrics.SecretDeletedTotal.Inc()
	return nil
}

//
// ---------- kv/file payloads ----------
//

// Put seals value as a new version of an existing kv or file secret. The
// version number is reserved by the store inside one transaction and handed
// to the sealer before encryption, so the AAD binding can never drift from
// the version actually persisted - see store.CreateSecretVersion's comment.
func (s *Service) Put(ctx context.Context, name string, value []byte, contentType, actor string) (*store.SecretVersion, error) {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return nil, err
	}
	if sec.Type == store.SecretTypeCertificate {
		return nil, errors.New("certificate secrets are materialized from their linked certificate, not written directly")
	}
	if sec.Disabled {
		return nil, fmt.Errorf("secret %q is disabled", sec.Name)
	}
	v, err := s.st.CreateSecretVersion(ctx, sec.ID, contentType, actor, func(secretID int64, version int) (store.SealedVersion, error) {
		env, err := s.vault.Seal(value, aad(secretID, version))
		if err != nil {
			return store.SealedVersion{}, fmt.Errorf("seal secret: %w", err)
		}
		sum := sha256.Sum256(value)
		return store.SealedVersion{
			PayloadEnc:    env,
			PayloadSHA256: hex.EncodeToString(sum[:]),
			SizeBytes:     int64(len(value)),
		}, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, actor, "secret.put", sec.Name, fmt.Sprintf("version=%d size=%d", v.Version, len(value)))
	metrics.SecretPutTotal.WithLabelValues(sec.Type).Inc()
	return v, nil
}

// GetLatest opens the newest, non-destroyed version of a kv or file secret
// and returns its plaintext.
func (s *Service) GetLatest(ctx context.Context, name string) (*store.Secret, []byte, error) {
	sec, err := s.resolveOpenable(ctx, name)
	if err != nil {
		metrics.SecretReadTotal.WithLabelValues("", "denied").Inc()
		return nil, nil, err
	}
	v, err := s.st.GetLatestSecretVersion(ctx, sec.ID)
	if err != nil {
		metrics.SecretReadTotal.WithLabelValues(sec.Type, "denied").Inc()
		return nil, nil, err
	}
	pt, err := s.open(sec, v)
	if err != nil {
		metrics.SecretReadTotal.WithLabelValues(sec.Type, "denied").Inc()
		return nil, nil, err
	}
	metrics.SecretReadTotal.WithLabelValues(sec.Type, "success").Inc()
	return sec, pt, err
}

// GetVersion opens one specific, possibly non-current version.
func (s *Service) GetVersion(ctx context.Context, name string, version int) (*store.Secret, []byte, error) {
	sec, err := s.resolveOpenable(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	v, err := s.st.GetSecretVersion(ctx, sec.ID, version)
	if err != nil {
		return nil, nil, err
	}
	pt, err := s.open(sec, v)
	return sec, pt, err
}

func (s *Service) resolveOpenable(ctx context.Context, name string) (*store.Secret, error) {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return nil, err
	}
	if sec.Type == store.SecretTypeCertificate {
		return nil, fmt.Errorf("%q is a certificate secret; use Materialize", sec.Name)
	}
	if sec.Disabled {
		return nil, fmt.Errorf("secret %q is disabled", sec.Name)
	}
	return sec, nil
}

func (s *Service) open(sec *store.Secret, v *store.SecretVersion) ([]byte, error) {
	if v.Destroyed {
		return nil, fmt.Errorf("version %d of %q has been destroyed", v.Version, sec.Name)
	}
	pt, err := s.vault.Open(v.PayloadEnc, aad(sec.ID, v.Version))
	if err != nil {
		return nil, fmt.Errorf("open secret: %w", err)
	}
	return pt, nil
}

// Versions lists every version of a secret, newest first.
func (s *Service) Versions(ctx context.Context, name string) (*store.Secret, []*store.SecretVersion, error) {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return nil, nil, err
	}
	versions, err := s.st.ListSecretVersions(ctx, sec.ID)
	return sec, versions, err
}

// DestroyVersion permanently scrubs one version's ciphertext, keeping the
// row (and its place in the version sequence) for history.
func (s *Service) DestroyVersion(ctx context.Context, name string, version int, actor string) error {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return err
	}
	v, err := s.st.GetSecretVersion(ctx, sec.ID, version)
	if err != nil {
		return err
	}
	if err := s.st.DestroySecretVersion(ctx, v.ID); err != nil {
		return err
	}
	s.audit(ctx, actor, "secret.version_destroy", sec.Name, fmt.Sprintf("version=%d", version))
	return nil
}

//
// ---------- materialization ----------
//

// Materialize resolves a secret's current content into the file(s) a
// consumer (the CLI, or a future CSI Mount) actually writes out, plus a
// version marker that changes exactly when the content does - the CSI
// object_version a later phase needs for rotation.
//
// kv secrets materialize to one file, "value". file secrets materialize to
// one file named after their stored content type, defaulting to "value".
// certificate secrets materialize to the standard tls.crt/tls.key/ca.crt
// triad, resolved fresh from the linked certificate through ca.Service -
// tls.crt is the full chain (leaf + issuers), matching what nginx/Kubernetes
// serving expects, and ca.crt is the issuer chain alone, for trust bundles.
func (s *Service) Materialize(ctx context.Context, name string) (*store.Secret, []File, string, error) {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return nil, nil, "", err
	}
	if sec.Disabled {
		return nil, nil, "", fmt.Errorf("secret %q is disabled", sec.Name)
	}
	switch sec.Type {
	case store.SecretTypeCertificate:
		files, version, err := s.materializeCertificate(ctx, sec)
		return sec, files, version, err
	default:
		v, err := s.st.GetLatestSecretVersion(ctx, sec.ID)
		if err != nil {
			return nil, nil, "", err
		}
		pt, err := s.open(sec, v)
		if err != nil {
			return nil, nil, "", err
		}
		fname := strings.TrimSpace(v.ContentType)
		if fname == "" {
			fname = "value"
		}
		return sec, []File{{Name: fname, Data: pt}}, v.PayloadSHA256, nil
	}
}

func (s *Service) materializeCertificate(ctx context.Context, sec *store.Secret) ([]File, string, error) {
	if s.ca == nil {
		return nil, "", errors.New("certificate secrets are unavailable: no CA service is configured")
	}
	if sec.CertID == nil {
		return nil, "", fmt.Errorf("secret %q has no linked certificate", sec.Name)
	}
	cert, err := s.ca.GetCertificate(ctx, *sec.CertID)
	if err != nil {
		return nil, "", fmt.Errorf("resolve certificate %d: %w", *sec.CertID, err)
	}
	full, err := s.ca.CertChainPEM(ctx, cert)
	if err != nil {
		return nil, "", fmt.Errorf("build full chain: %w", err)
	}
	key, err := s.ca.CertKeyPEM(ctx, cert)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt private key: %w", err)
	}
	caRec, err := s.ca.GetCA(ctx, cert.CAID)
	if err != nil {
		return nil, "", fmt.Errorf("resolve issuing CA: %w", err)
	}
	chain, err := s.ca.CAChainPEM(ctx, caRec)
	if err != nil {
		return nil, "", fmt.Errorf("build issuer chain: %w", err)
	}
	// The version marker must change exactly when the materialized content
	// would - the certificate's serial does that (a renewal always mints a
	// new one) without needing a version scheme of its own for certificates.
	version := "cert:" + cert.SerialHex
	return []File{
		{Name: "tls.crt", Data: full},
		{Name: "tls.key", Data: key},
		{Name: "ca.crt", Data: chain},
	}, version, nil
}

//
// ---------- Kubernetes bindings ----------
//

// Bind authorizes a Kubernetes (namespace, ServiceAccount) pair to fetch a
// secret. Either may be "*" to match anything; both are glob-matched with
// path.Match syntax by MatchesBinding / the CSI provider added in a later
// phase. authMethod scopes the binding to a named CSI trust domain; "*" (the
// default) matches any trust domain.
func (s *Service) Bind(ctx context.Context, name, namespace, serviceAccount, authMethod string, expiresAt *time.Time, actor string) (*store.SecretBinding, error) {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return nil, err
	}
	ns := nzGlob(namespace)
	sa := nzGlob(serviceAccount)
	method := nzGlob(authMethod)
	if _, err := path.Match(ns, "probe"); err != nil {
		return nil, fmt.Errorf("invalid namespace pattern %q: %w", ns, err)
	}
	if _, err := path.Match(sa, "probe"); err != nil {
		return nil, fmt.Errorf("invalid service account pattern %q: %w", sa, err)
	}
	if _, err := path.Match(method, "probe"); err != nil {
		return nil, fmt.Errorf("invalid auth method pattern %q: %w", method, err)
	}
	b, err := s.st.CreateSecretBinding(ctx, &store.SecretBinding{
		SecretID:          sec.ID,
		K8sNamespace:      ns,
		K8sServiceAccount: sa,
		K8sAuthMethod:     method,
		ExpiresAt:         expiresAt,
		CreatedBy:         actor,
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, actor, "secret.bind", sec.Name, fmt.Sprintf("namespace=%s sa=%s auth_method=%s", ns, sa, method))
	return b, nil
}

// Unbind revokes one binding.
func (s *Service) Unbind(ctx context.Context, bindingID int64, actor string) error {
	if err := s.st.DeleteSecretBinding(ctx, bindingID); err != nil {
		return err
	}
	s.audit(ctx, actor, "secret.unbind", fmt.Sprint(bindingID), "")
	return nil
}

// Bindings lists every binding for one secret.
func (s *Service) Bindings(ctx context.Context, name string) ([]*store.SecretBinding, error) {
	sec, err := s.st.GetSecretByName(ctx, normalizeName(name))
	if err != nil {
		return nil, err
	}
	return s.st.ListSecretBindings(ctx, sec.ID)
}

// MatchesBinding reports whether a binding authorizes the given namespace,
// service account, and CSI trust domain, honoring "*" glob patterns and
// expiry.
//
// authMethod is the name of the trust domain (k8s_auth_methods row) whose
// Verifier validated the requesting token. A binding's K8sAuthMethod of "*"
// (the default) authorizes any trust domain; otherwise it must glob-match the
// request's method. This is what stops a token from cluster A from satisfying
// a binding scoped to cluster B even when both use the same (namespace,
// ServiceAccount).
func MatchesBinding(b *store.SecretBinding, namespace, serviceAccount, authMethod string) bool {
	if !b.Usable() {
		return false
	}
	nsOK, _ := path.Match(b.K8sNamespace, namespace)
	saOK, _ := path.Match(b.K8sServiceAccount, serviceAccount)
	methodOK := b.K8sAuthMethod == "*"
	if !methodOK {
		methodOK, _ = path.Match(b.K8sAuthMethod, authMethod)
	}
	return nsOK && saOK && methodOK
}

//
// ---------- helpers ----------
//

func normalizeName(name string) string { return strings.TrimSpace(name) }

func nzGlob(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "*"
	}
	return v
}

func (s *Service) audit(ctx context.Context, actor, action, target, detail string) {
	if actor == "" {
		actor = "system"
	}
	// Audit failures must never mask the operation that succeeded.
	_ = s.st.Audit(ctx, actor, action, target, detail, "")
}

// AuditWithIP records an action including the caller's address, for web
// handlers that have one.
func (s *Service) AuditWithIP(ctx context.Context, actor, action, target, detail, ip string) {
	_ = s.st.Audit(ctx, actor, action, target, detail, ip)
}
