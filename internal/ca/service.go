// Package ca is the business layer shared by the CLI, the web portal and the
// REST API. Every capability is implemented exactly once, here.
package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/metrics"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
)

// Service coordinates the PKI engine, the database and secret handling.
type Service struct {
	cfg  *config.Config
	st   *store.Store
	box  *secret.Box
	sink EventSink
}

// EventSink is invoked (best-effort) after every audit record is written, so
// an observer such as the webhook dispatcher can react to state-changing
// actions. It must be fast and non-fatal: the web layer wires it to the
// dispatcher, which only enqueues a durable delivery row.
type EventSink func(ctx context.Context, actor, action, target, detail, ip string)

// SetEventSink installs the observer invoked after each audit write. It is
// safe to call once at startup; a nil sink disables eventing.
func (s *Service) SetEventSink(sink EventSink) { s.sink = sink }

// New builds a Service from a validated config and an open store.
func New(cfg *config.Config, st *store.Store) (*Service, error) {
	key, err := cfg.MasterKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, st: st, box: box}, nil
}

// Store exposes the underlying store for auth and admin operations.
func (s *Service) Store() *store.Store { return s.st }

// Config exposes the loaded configuration.
func (s *Service) Config() *config.Config { return s.cfg }

// Box exposes the encryption helper (used for config secrets such as the LDAP
// bind password).
func (s *Service) Box() *secret.Box { return s.box }

//
// ---------- CA management ----------
//

// CreateCAInput describes a new certificate authority.
type CreateCAInput struct {
	Name          string      `json:"name"`
	Subject       pki.Subject `json:"subject"`
	KeyType       string      `json:"key_type"`
	Days          int         `json:"days"`
	ParentRef     string      `json:"parent"` // empty = self-signed root
	PathLen       int         `json:"path_len"`
	CRLDistPoints []string    `json:"crl_distribution_points"`
	OCSPServers   []string    `json:"ocsp_servers"`
	PermittedDNS  []string    `json:"permitted_dns_domains"`
	MakeDefault   bool        `json:"make_default"`
	Actor         string      `json:"-"`
}

// CreateCA generates a root or intermediate CA and stores it.
func (s *Service) CreateCA(ctx context.Context, in CreateCAInput) (*store.CA, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = in.Subject.CommonName
	}
	if name == "" {
		return nil, errors.New("a CA name is required")
	}
	if err := in.Subject.Validate(); err != nil {
		return nil, err
	}
	kt, err := pki.ParseKeyType(firstNonEmpty(in.KeyType, s.cfg.CA.DefaultKeyType, string(pki.KeyRSA4096)))
	if err != nil {
		return nil, err
	}
	days := in.Days
	if days <= 0 {
		days = s.cfg.CA.DefaultCADays
	}

	params := pki.CAParams{
		Subject:             in.Subject,
		KeyType:             kt,
		Days:                days,
		PathLen:             in.PathLen,
		CRLDistPoints:       firstNonEmptySlice(in.CRLDistPoints, s.cfg.CA.CRLDistPoints),
		OCSPServers:         firstNonEmptySlice(in.OCSPServers, s.cfg.CA.OCSPServers),
		PermittedDNSDomains: in.PermittedDNS,
	}

	var parent *store.CA
	if ref := strings.TrimSpace(in.ParentRef); ref != "" && ref != "none" {
		parent, err = s.st.GetCAByRef(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("parent CA %q: %w", ref, err)
		}
		parentCert, err := pki.ParseCertPEM([]byte(parent.CertPEM))
		if err != nil {
			return nil, fmt.Errorf("parse parent CA certificate: %w", err)
		}
		parentKey, err := s.decryptKey(parent.KeyEnc)
		if err != nil {
			return nil, fmt.Errorf("unlock parent CA key: %w", err)
		}
		params.Parent = parentCert
		params.ParentKey = parentKey
	}

	res, err := pki.CreateCA(params)
	if err != nil {
		return nil, err
	}
	keyEnc, err := s.box.Encrypt(res.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt CA key: %w", err)
	}

	rec := &store.CA{
		Name:        name,
		Slug:        s.uniqueSlug(ctx, name),
		Subject:     in.Subject.String(),
		SubjectJSON: in.Subject.JSON(),
		SerialHex:   res.SerialHex,
		KeyType:     string(res.KeyType),
		CertPEM:     string(res.CertPEM),
		KeyEnc:      keyEnc,
		IsRoot:      parent == nil,
		PathLen:     in.PathLen,
		NotBefore:   res.Certificate.NotBefore,
		NotAfter:    res.Certificate.NotAfter,
		Status:      store.StatusActive,
		Fingerprint: res.Fingerprint,
		CreatedBy:   in.Actor,
	}
	if parent != nil {
		id := parent.ID
		rec.ParentID = &id
	}
	saved, err := s.st.CreateCA(ctx, rec)
	if err != nil {
		return nil, err
	}
	if in.MakeDefault {
		if err := s.st.SetDefaultCA(ctx, saved.ID); err != nil {
			return nil, err
		}
		saved.IsDefault = true
	}
	s.audit(ctx, in.Actor, "ca.create", saved.Name,
		fmt.Sprintf("serial=%s key=%s days=%d root=%t", saved.SerialHex, saved.KeyType, days, saved.IsRoot))
	return saved, nil
}

// ListCAs returns every CA.
func (s *Service) ListCAs(ctx context.Context) ([]*store.CA, error) { return s.st.ListCAs(ctx) }

// GetCA fetches a CA by ID.
func (s *Service) GetCA(ctx context.Context, id int64) (*store.CA, error) { return s.st.GetCA(ctx, id) }

// ResolveCA finds a CA by ID, slug or name; an empty ref returns the default.
func (s *Service) ResolveCA(ctx context.Context, ref string) (*store.CA, error) {
	return s.st.GetCAByRef(ctx, ref)
}

// SetDefaultCA marks a CA as the issuance default.
func (s *Service) SetDefaultCA(ctx context.Context, id int64, actor string) error {
	if err := s.st.SetDefaultCA(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, "ca.set_default", fmt.Sprint(id), "")
	return nil
}

// SetCAStatus enables or disables issuance from a CA.
func (s *Service) SetCAStatus(ctx context.Context, id int64, status, actor string) error {
	if status != store.StatusActive && status != store.StatusDisabled {
		return fmt.Errorf("status must be %q or %q", store.StatusActive, store.StatusDisabled)
	}
	if err := s.st.SetCAStatus(ctx, id, status); err != nil {
		return err
	}
	s.audit(ctx, actor, "ca.status", fmt.Sprint(id), status)
	return nil
}

// DeleteCA removes a CA and all certificates it issued.
func (s *Service) DeleteCA(ctx context.Context, id int64, actor string) error {
	c, err := s.st.GetCA(ctx, id)
	if err != nil {
		return err
	}
	if err := s.st.DeleteCA(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, "ca.delete", c.Name, "cascade delete of issued certificates")
	return nil
}

// CAKey decrypts and parses a CA private key.
func (s *Service) CAKey(ctx context.Context, c *store.CA) (crypto.PrivateKey, error) {
	return s.decryptKey(c.KeyEnc)
}

// CAKeyPEM returns the decrypted CA private key in PEM form.
func (s *Service) CAKeyPEM(ctx context.Context, c *store.CA) ([]byte, error) {
	return s.box.Decrypt(c.KeyEnc)
}

// CAChain returns the CA certificate followed by its ancestors up to the root.
func (s *Service) CAChain(ctx context.Context, c *store.CA) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	cur := c
	for i := 0; i < 16; i++ { // guard against a malformed parent cycle
		cert, err := pki.ParseCertPEM([]byte(cur.CertPEM))
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
		if cur.ParentID == nil {
			break
		}
		parent, err := s.st.GetCA(ctx, *cur.ParentID)
		if err != nil {
			break
		}
		cur = parent
	}
	return chain, nil
}

// CAChainPEM concatenates the CA chain as PEM (leaf CA first).
func (s *Service) CAChainPEM(ctx context.Context, c *store.CA) ([]byte, error) {
	chain, err := s.CAChain(ctx, c)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, cert := range chain {
		out = append(out, pki.EncodeCertPEM(cert.Raw)...)
	}
	return out, nil
}

//
// ---------- Issuance ----------
//

// IssueMode selects where the key material comes from.
type IssueMode string

const (
	// ModeGenerate creates a new key and CSR server-side.
	ModeGenerate IssueMode = "generate"
	// ModeCSR signs a CSR supplied by the requester.
	ModeCSR IssueMode = "csr"
)

// IssueInput describes a certificate request.
type IssueInput struct {
	CARef   string      `json:"ca"`
	Mode    IssueMode   `json:"mode"`
	Subject pki.Subject `json:"subject"`
	SANs    []string    `json:"sans"`
	KeyType string      `json:"key_type"`
	Profile string      `json:"profile"`
	Days    int         `json:"days"`

	// CSRPEM is required when Mode is ModeCSR.
	CSRPEM string `json:"csr_pem"`
	// KeyPEM optionally stores the requester's existing private key so the
	// bundle can be re-downloaded later. It must match the CSR.
	KeyPEM string `json:"key_pem"`
	// StoreKey controls whether a generated key is retained for later
	// download. Disable it for a stricter, download-once workflow.
	StoreKey *bool `json:"store_key"`

	Note  string `json:"note"`
	Actor string `json:"-"`
}

// IssueResult carries the stored certificate plus any freshly generated key.
// PrivateKeyPEM is populated only for this response; retrieve it later through
// CertKeyPEM when the key was stored.
type IssueResult struct {
	Certificate   *store.Certificate `json:"certificate"`
	PrivateKeyPEM string             `json:"private_key_pem,omitempty"`
	CSRPEM        string             `json:"csr_pem,omitempty"`
	ChainPEM      string             `json:"chain_pem,omitempty"`
}

// Issue signs a certificate, either from a supplied CSR or from a key pair it
// generates on the requester's behalf.
func (s *Service) Issue(ctx context.Context, in IssueInput) (*IssueResult, error) {
	caRec, err := s.st.GetCAByRef(ctx, in.CARef)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, s.noIssuerError(ctx, in.CARef)
		}
		return nil, err
	}
	if err := checkCanIssue(caRec); err != nil {
		return nil, err
	}
	issuerCert, err := pki.ParseCertPEM([]byte(caRec.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	issuerKey, err := s.decryptKey(caRec.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("unlock CA key: %w", err)
	}
	profile, err := pki.ParseProfile(in.Profile)
	if err != nil {
		return nil, err
	}
	days := in.Days
	if days <= 0 {
		days = s.cfg.CA.DefaultCertDays
	}

	var (
		csr        *x509.CertificateRequest
		csrPEM     string
		genKeyPEM  string
		keyTypeStr string
	)

	mode := in.Mode
	if mode == "" {
		if strings.TrimSpace(in.CSRPEM) != "" {
			mode = ModeCSR
		} else {
			mode = ModeGenerate
		}
	}

	switch mode {
	case ModeCSR:
		if strings.TrimSpace(in.CSRPEM) == "" {
			return nil, errors.New("csr_pem is required when mode is \"csr\"")
		}
		csr, err = pki.ParseCSR([]byte(in.CSRPEM))
		if err != nil {
			return nil, err
		}
		csrPEM = normalizePEM(in.CSRPEM)
		keyTypeStr = string(pki.KeyTypeOf(csr.PublicKey))
		if kp := strings.TrimSpace(in.KeyPEM); kp != "" {
			key, err := pki.ParsePrivateKeyPEM([]byte(kp))
			if err != nil {
				return nil, fmt.Errorf("parse supplied private key: %w", err)
			}
			if err := pki.KeyMatchesCSR(key, csr); err != nil {
				return nil, fmt.Errorf("supplied key does not match the CSR: %w", err)
			}
			genKeyPEM = normalizePEM(kp)
		}

	case ModeGenerate:
		if err := in.Subject.Validate(); err != nil {
			return nil, err
		}
		kt, err := pki.ParseKeyType(firstNonEmpty(in.KeyType, s.cfg.CA.DefaultKeyType))
		if err != nil {
			return nil, err
		}
		sans, err := pki.ParseSANs(in.SANs)
		if err != nil {
			return nil, err
		}
		gen, err := pki.GenerateCSR(pki.CSRRequest{Subject: in.Subject, SANs: sans, KeyType: kt})
		if err != nil {
			return nil, err
		}
		csr, err = pki.ParseCSR(gen.CSRPEM)
		if err != nil {
			return nil, err
		}
		csrPEM = string(gen.CSRPEM)
		genKeyPEM = string(gen.PrivateKeyPEM)
		keyTypeStr = string(gen.KeyType)

	default:
		return nil, fmt.Errorf("unknown issue mode %q (use \"generate\" or \"csr\")", in.Mode)
	}

	signParams := pki.SignParams{
		CSR:           csr,
		Issuer:        issuerCert,
		IssuerKey:     issuerKey,
		Profile:       profile,
		Days:          days,
		CRLDistPoints: s.cfg.CA.CRLDistPoints,
		OCSPServers:   s.cfg.CA.OCSPServers,
	}
	// SANs supplied alongside a CSR override what the CSR carries, which is
	// how operators correct a request without asking for a new one.
	if mode == ModeCSR && len(in.SANs) > 0 {
		sans, err := pki.ParseSANs(in.SANs)
		if err != nil {
			return nil, err
		}
		signParams.SANOverride = &sans
	}
	if mode == ModeCSR && strings.TrimSpace(in.Subject.CommonName) != "" {
		sub := in.Subject
		signParams.SubjectOverride = &sub
	}

	res, err := pki.Sign(signParams)
	if err != nil {
		return nil, err
	}

	storeKey := true
	if in.StoreKey != nil {
		storeKey = *in.StoreKey
	}
	keyEnc := ""
	if storeKey && genKeyPEM != "" {
		keyEnc, err = s.box.EncryptString(genKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("encrypt private key: %w", err)
		}
	}

	info := pki.Describe(res.Certificate)
	rec := &store.Certificate{
		CAID:        caRec.ID,
		SerialHex:   res.SerialHex,
		CommonName:  res.Certificate.Subject.CommonName,
		Subject:     info.Subject,
		SANsJSON:    store.EncodeSANs(info.SANs),
		Profile:     string(profile),
		KeyType:     keyTypeStr,
		CertPEM:     string(res.CertPEM),
		KeyEnc:      keyEnc,
		CSRPEM:      csrPEM,
		Fingerprint: res.Fingerprint,
		NotBefore:   res.Certificate.NotBefore,
		NotAfter:    res.Certificate.NotAfter,
		Status:      store.StatusActive,
		RequestedBy: in.Actor,
		Note:        in.Note,
	}
	saved, err := s.st.CreateCertificate(ctx, rec)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, in.Actor, "cert.issue", saved.CommonName,
		fmt.Sprintf("serial=%s ca=%s profile=%s days=%d mode=%s key_stored=%t",
			saved.SerialHex, caRec.Name, profile, days, mode, keyEnc != ""))

	metrics.CertIssuedTotal.WithLabelValues(caRec.Name, string(profile)).Inc()

	chainPEM, _ := s.CAChainPEM(ctx, caRec)
	out := &IssueResult{Certificate: saved, CSRPEM: csrPEM, ChainPEM: string(chainPEM)}
	// Always hand the key back on the issuing response, even when it is not
	// retained server-side - otherwise the requester could never use the cert.
	if genKeyPEM != "" && mode == ModeGenerate {
		out.PrivateKeyPEM = genKeyPEM
	}
	return out, nil
}

// GenerateCSRInput describes a standalone CSR generation (no signing).
type GenerateCSRInput struct {
	Subject pki.Subject `json:"subject"`
	SANs    []string    `json:"sans"`
	KeyType string      `json:"key_type"`
}

// GenerateCSRResult carries a CSR and its new key. Nothing is persisted.
type GenerateCSRResult struct {
	CSRPEM        string      `json:"csr_pem"`
	PrivateKeyPEM string      `json:"private_key_pem"`
	KeyType       string      `json:"key_type"`
	Info          pki.CSRInfo `json:"info"`
}

// GenerateCSR produces a key and CSR for users who want to sign elsewhere, or
// who want to review the request before submitting it.
func (s *Service) GenerateCSR(ctx context.Context, in GenerateCSRInput) (*GenerateCSRResult, error) {
	if err := in.Subject.Validate(); err != nil {
		return nil, err
	}
	kt, err := pki.ParseKeyType(firstNonEmpty(in.KeyType, s.cfg.CA.DefaultKeyType))
	if err != nil {
		return nil, err
	}
	sans, err := pki.ParseSANs(in.SANs)
	if err != nil {
		return nil, err
	}
	gen, err := pki.GenerateCSR(pki.CSRRequest{Subject: in.Subject, SANs: sans, KeyType: kt})
	if err != nil {
		return nil, err
	}
	parsed, err := pki.ParseCSR(gen.CSRPEM)
	if err != nil {
		return nil, err
	}
	return &GenerateCSRResult{
		CSRPEM:        string(gen.CSRPEM),
		PrivateKeyPEM: string(gen.PrivateKeyPEM),
		KeyType:       string(gen.KeyType),
		Info:          pki.DescribeCSR(parsed),
	}, nil
}

//
// ---------- Certificate retrieval ----------
//

// GetCertificate fetches one certificate by ID.
func (s *Service) GetCertificate(ctx context.Context, id int64) (*store.Certificate, error) {
	return s.st.GetCertificate(ctx, id)
}

// FindCertificate resolves a certificate by numeric ID or hex serial.
func (s *Service) FindCertificate(ctx context.Context, ref string) (*store.Certificate, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("a certificate id or serial is required")
	}
	if id, err := parseInt64(ref); err == nil {
		if c, err := s.st.GetCertificate(ctx, id); err == nil {
			return c, nil
		}
	}
	return s.st.GetCertificateBySerial(ctx, ref)
}

// Search runs a filtered certificate query.
func (s *Service) Search(ctx context.Context, f store.CertFilter) ([]*store.Certificate, int, error) {
	list, total, err := s.st.SearchCertificates(ctx, f)
	if err == nil {
		metrics.CertSearchTotal.WithLabelValues(f.Status).Inc()
	}
	return list, total, err
}

// CertKeyPEM returns the stored private key for a certificate, if retained.
func (s *Service) CertKeyPEM(ctx context.Context, c *store.Certificate) ([]byte, error) {
	if c.KeyEnc == "" {
		return nil, errors.New("no private key is stored for this certificate " +
			"(it was issued from a CSR, or key storage was disabled)")
	}
	return s.box.Decrypt(c.KeyEnc)
}

// CertChainPEM returns the certificate followed by the full issuing chain.
func (s *Service) CertChainPEM(ctx context.Context, c *store.Certificate) ([]byte, error) {
	caRec, err := s.st.GetCA(ctx, c.CAID)
	if err != nil {
		return nil, err
	}
	chain, err := s.CAChainPEM(ctx, caRec)
	if err != nil {
		return nil, err
	}
	return append([]byte(c.CertPEM), chain...), nil
}

// CertBundleP12 builds a password-protected PKCS#12 bundle.
func (s *Service) CertBundleP12(ctx context.Context, c *store.Certificate, password string) ([]byte, error) {
	keyPEM, err := s.CertKeyPEM(ctx, c)
	if err != nil {
		return nil, err
	}
	key, err := pki.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := pki.ParseCertPEM([]byte(c.CertPEM))
	if err != nil {
		return nil, err
	}
	caRec, err := s.st.GetCA(ctx, c.CAID)
	if err != nil {
		return nil, err
	}
	chain, err := s.CAChain(ctx, caRec)
	if err != nil {
		return nil, err
	}
	return pki.BuildPKCS12(key, leaf, chain, password)
}

// Describe parses and summarises a stored certificate.
func (s *Service) Describe(c *store.Certificate) (pki.CertInfo, error) {
	cert, err := pki.ParseCertPEM([]byte(c.CertPEM))
	if err != nil {
		return pki.CertInfo{}, err
	}
	return pki.Describe(cert), nil
}

//
// ---------- Revocation & CRL ----------
//

// Revoke marks a certificate revoked with an RFC 5280 reason.
func (s *Service) Revoke(ctx context.Context, id int64, reason int, actor string) error {
	c, err := s.st.GetCertificate(ctx, id)
	if err != nil {
		return err
	}
	if err := s.st.RevokeCertificate(ctx, id, reason); err != nil {
		return err
	}
	s.audit(ctx, actor, "cert.revoke", c.CommonName,
		fmt.Sprintf("serial=%s reason=%s", c.SerialHex, pki.ReasonName(reason)))

	metrics.CertRevokedTotal.WithLabelValues(pki.ReasonName(reason)).Inc()
	return nil
}

// GenerateCRL issues a fresh CRL for a CA and returns DER and PEM encodings.
func (s *Service) GenerateCRL(ctx context.Context, caID int64, actor string) (der, pemBytes []byte, err error) {
	caRec, err := s.st.GetCA(ctx, caID)
	if err != nil {
		return nil, nil, err
	}
	// Signing a CRL needs the CA key, which a trust anchor or a pending
	// authority does not have.
	if caRec.Pending() {
		return nil, nil, fmt.Errorf("authority %q has no certificate yet, so it has no CRL", caRec.Name)
	}
	if !caRec.HasKey() {
		return nil, nil, fmt.Errorf("goca holds no private key for %q, so it cannot sign a CRL. "+
			"Publish that authority's CRL from wherever it is operated", caRec.Name)
	}
	issuerCert, err := pki.ParseCertPEM([]byte(caRec.CertPEM))
	if err != nil {
		return nil, nil, err
	}
	issuerKey, err := s.decryptKey(caRec.KeyEnc)
	if err != nil {
		return nil, nil, err
	}
	revoked, err := s.st.RevokedCertificates(ctx, caID)
	if err != nil {
		return nil, nil, err
	}
	entries := make([]pki.RevokedEntry, 0, len(revoked))
	for _, r := range revoked {
		at := time.Now().UTC()
		if r.RevokedAt != nil {
			at = *r.RevokedAt
		}
		entries = append(entries, pki.RevokedEntry{SerialHex: r.SerialHex, RevokedAt: at, Reason: r.RevokeCode})
	}
	// Subordinate authorities this CA retired belong on the same list.
	caRevs, err := s.st.CARevocations(ctx, caID)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range caRevs {
		entries = append(entries, pki.RevokedEntry{
			SerialHex: r.SerialHex, RevokedAt: r.RevokedAt, Reason: r.Reason})
	}
	number, err := s.st.NextCRLNumber(ctx, caID)
	if err != nil {
		return nil, nil, err
	}
	der, pemBytes, err = pki.CreateCRL(pki.CRLParams{
		Issuer:    issuerCert,
		IssuerKey: issuerKey,
		Number:    number,
		ValidDays: s.cfg.CA.CRLDays,
		Revoked:   entries,
	})
	if err != nil {
		return nil, nil, err
	}
	s.audit(ctx, actor, "crl.generate", caRec.Name,
		fmt.Sprintf("number=%d entries=%d", number, len(entries)))
	return der, pemBytes, nil
}

//
// ---------- helpers ----------
//

func (s *Service) decryptKey(enc string) (crypto.PrivateKey, error) {
	pemBytes, err := s.box.Decrypt(enc)
	if err != nil {
		return nil, err
	}
	return pki.ParsePrivateKeyPEM(pemBytes)
}

func (s *Service) audit(ctx context.Context, actor, action, target, detail string) {
	s.recordAudit(ctx, actor, action, target, detail, "")
}

// AuditWithIP records an action including the caller's address.
func (s *Service) AuditWithIP(ctx context.Context, actor, action, target, detail, ip string) {
	s.recordAudit(ctx, actor, action, target, detail, ip)
}

// recordAudit is the single funnel every audit write passes through. It
// persists the row (best-effort, so a failure never masks the operation that
// succeeded) and then notifies the event sink, if one is installed.
func (s *Service) recordAudit(ctx context.Context, actor, action, target, detail, ip string) {
	if actor == "" {
		actor = "system"
	}
	_ = s.st.Audit(ctx, actor, action, target, detail, ip)
	if s.sink != nil {
		s.sink(ctx, actor, action, target, detail, ip)
	}
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify makes a URL-safe identifier out of a CA name.
func Slugify(s string) string {
	out := slugRE.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
	out = strings.Trim(out, "-")
	if out == "" {
		out = "ca"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func (s *Service) uniqueSlug(ctx context.Context, name string) string {
	base := Slugify(name)
	slug := base
	for i := 2; i < 100; i++ {
		if _, err := s.st.GetCABySlug(ctx, slug); errors.Is(err, store.ErrNotFound) {
			return slug
		}
		slug = fmt.Sprintf("%s-%d", base, i)
	}
	return fmt.Sprintf("%s-%d", base, time.Now().Unix())
}

// noIssuerError explains why no authority was available. Resolving a default
// only considers CAs that can sign, so "not found" can mean an empty database,
// a named CA that does not exist, or authorities that all happen to be
// unusable - three situations with three different fixes.
func (s *Service) noIssuerError(ctx context.Context, ref string) error {
	if strings.TrimSpace(ref) != "" {
		return fmt.Errorf("no certificate authority matches %q", ref)
	}
	all, err := s.st.ListCAs(ctx)
	if err != nil || len(all) == 0 {
		return errors.New("no CA available; create one first with `goca ca create --wizard`, " +
			"the web wizard, or import an existing one with `goca ca import`")
	}
	// Some authorities exist but none can issue; report why for each.
	var reasons []string
	for _, c := range all {
		if err := checkCanIssue(c); err != nil {
			reasons = append(reasons, err.Error())
		}
	}
	if len(reasons) == 1 {
		return errors.New(reasons[0])
	}
	return fmt.Errorf("no authority can issue right now:\n  - %s", strings.Join(reasons, "\n  - "))
}

// checkCanIssue explains, in operator terms, why a CA cannot sign right now.
func checkCanIssue(c *store.CA) error {
	switch {
	case c.Status == store.StatusPending:
		return fmt.Errorf("authority %q is still waiting for its signed certificate. "+
			"Send its CSR to the external authority, then import the result with "+
			"`goca ca import-signed %s --cert signed.crt`", c.Name, c.Slug)
	case !c.HasKey():
		return fmt.Errorf("authority %q is a trust anchor: goca holds its certificate but not "+
			"its private key, so it cannot sign. Issue from a CA that has a key", c.Name)
	case c.Status != store.StatusActive:
		return fmt.Errorf("authority %q is %s and cannot issue certificates", c.Name, c.Status)
	case c.Expired():
		return fmt.Errorf("authority %q expired on %s", c.Name, c.NotAfter.Format("2006-01-02"))
	}
	return nil
}

// normalizePEM trims stray whitespace and guarantees the trailing newline that
// PEM files conventionally carry, so exported files match what was uploaded.
func normalizePEM(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return s + "\n"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstNonEmptySlice(vals ...[]string) []string {
	for _, v := range vals {
		if len(v) > 0 {
			return v
		}
	}
	return nil
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0, err
	}
	if fmt.Sprint(n) != strings.TrimSpace(s) {
		return 0, errors.New("not a plain integer")
	}
	return n, nil
}
