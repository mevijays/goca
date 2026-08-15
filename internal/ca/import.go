package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// This file implements running goca underneath an authority it does not own -
// a pfSense CA, a corporate root, an offline root on a USB stick. Three flows
// are supported, and all three are available from the CLI, the API and the
// portal:
//
//  1. SubordinateCSR + CompleteSubordinate
//     goca generates the key and a CSR, you get it signed by the external
//     authority, then import the signed certificate. The private key never
//     leaves this server. This is the recommended flow.
//
//  2. ImportCA with a certificate and its key
//     You already created the intermediate on the external side (pfSense can
//     export the pair). goca imports both and can issue immediately.
//
//  3. ImportCA with a certificate only
//     Stores a trust anchor so chains build and the root is downloadable.
//     It cannot issue, having no key.

// SubordinateCSRInput describes a subordinate CA request for an external
// authority to sign.
type SubordinateCSRInput struct {
	Name    string      `json:"name"`
	Subject pki.Subject `json:"subject"`
	KeyType string      `json:"key_type"`
	// ParentRef optionally names the trust anchor this will chain to, when it
	// has already been imported. It can also be linked later, at import time.
	ParentRef string `json:"parent"`
	Actor     string `json:"-"`
}

// SubordinateCSRResult carries the request to hand to the external authority.
type SubordinateCSRResult struct {
	CA     *store.CA   `json:"ca"`
	CSRPEM string      `json:"csr_pem"`
	Info   pki.CSRInfo `json:"info"`
}

// CreateSubordinateCSR generates a CA key pair, keeps the key encrypted in the
// database, and returns a CSR for an external authority to sign. The CA row is
// created in "pending" state and cannot issue until the signed certificate is
// imported with CompleteSubordinate.
func (s *Service) CreateSubordinateCSR(ctx context.Context, in SubordinateCSRInput) (*SubordinateCSRResult, error) {
	if err := in.Subject.Validate(); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = in.Subject.CommonName
	}
	kt, err := pki.ParseKeyType(firstNonEmpty(in.KeyType, s.cfg.CA.DefaultKeyType, string(pki.KeyRSA4096)))
	if err != nil {
		return nil, err
	}

	var parentID *int64
	if ref := strings.TrimSpace(in.ParentRef); ref != "" && ref != "none" {
		parent, err := s.st.GetCAByRef(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("parent authority %q: %w", ref, err)
		}
		id := parent.ID
		parentID = &id
	}

	gen, err := pki.CreateSubordinateCSR(pki.SubordinateCSRParams{Subject: in.Subject, KeyType: kt})
	if err != nil {
		return nil, err
	}
	keyEnc, err := s.box.Encrypt(gen.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt subordinate CA key: %w", err)
	}
	parsed, err := pki.ParseCSR(gen.CSRPEM)
	if err != nil {
		return nil, err
	}

	// A pending CA has no certificate yet, so it has no validity window. The
	// zero-ish window keeps it out of "expiring soon" views until completed.
	rec := &store.CA{
		Name:        name,
		Slug:        s.uniqueSlug(ctx, name),
		Subject:     in.Subject.String(),
		SubjectJSON: in.Subject.JSON(),
		KeyType:     string(kt),
		KeyEnc:      keyEnc,
		CSRPEM:      string(gen.CSRPEM),
		IsRoot:      false,
		ParentID:    parentID,
		Status:      store.StatusPending,
		External:    true,
		CreatedBy:   in.Actor,
	}
	saved, err := s.st.CreateCA(ctx, rec)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, in.Actor, "ca.csr_created", saved.Name,
		fmt.Sprintf("key=%s awaiting external signature", kt))

	return &SubordinateCSRResult{
		CA:     saved,
		CSRPEM: string(gen.CSRPEM),
		Info:   pki.DescribeCSR(parsed),
	}, nil
}

// CompleteSubordinateInput carries the signed certificate back from the
// external authority.
type CompleteSubordinateInput struct {
	CARef string `json:"ca"`
	// CertPEM is the signed subordinate CA certificate.
	CertPEM string `json:"cert_pem"`
	// ChainPEM optionally carries the issuer chain, whose certificates are
	// imported as trust anchors when they are not already known.
	ChainPEM    string `json:"chain_pem"`
	MakeDefault bool   `json:"make_default"`
	Actor       string `json:"-"`
}

// CompleteSubordinate imports the certificate an external authority issued for
// a pending CSR, matching it against the key goca kept.
func (s *Service) CompleteSubordinate(ctx context.Context, in CompleteSubordinateInput) (*store.CA, error) {
	rec, err := s.st.GetCAByRef(ctx, in.CARef)
	if err != nil {
		return nil, fmt.Errorf("authority %q: %w", in.CARef, err)
	}
	if rec.Status != store.StatusPending {
		return nil, fmt.Errorf("authority %q is not waiting for a signature (status: %s)",
			rec.Name, rec.Status)
	}
	if strings.TrimSpace(in.CertPEM) == "" {
		return nil, errors.New("the signed certificate is required")
	}

	certs, err := pki.ParseCertChainPEM([]byte(in.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("parse the signed certificate: %w", err)
	}
	cert := certs[0]
	// Some authorities hand back the leaf and its issuers in one file; treat
	// the extras as chain material.
	chainPEM := in.ChainPEM
	if len(certs) > 1 {
		for _, extra := range certs[1:] {
			chainPEM += string(pki.EncodeCertPEM(extra.Raw))
		}
	}

	if err := pki.ValidateCACertificate(cert); err != nil {
		return nil, err
	}
	// The certificate must belong to the key we generated, or it is useless.
	key, err := s.decryptKey(rec.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("unlock the pending CA key: %w", err)
	}
	if err := pki.MatchKeyToCertificate(key, cert); err != nil {
		return nil, fmt.Errorf("%w. This certificate was signed for a different request; "+
			"re-submit %s and import the certificate issued for it", err, rec.Name)
	}

	parentID, err := s.linkIssuer(ctx, cert, chainPEM, in.Actor)
	if err != nil {
		return nil, err
	}

	info := pki.Describe(cert)
	updated := &store.CA{
		CertPEM:        string(pki.EncodeCertPEM(cert.Raw)),
		SerialHex:      pki.SerialHex(cert.SerialNumber),
		Subject:        info.Subject,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		Fingerprint:    info.FingerprintSHA256,
		Status:         store.StatusActive,
		IsRoot:         pki.IsSelfSigned(cert),
		ParentID:       parentID,
		PathLen:        pki.PathLenOf(cert),
		SubjectKeyID:   info.SubjectKeyID,
		AuthorityKeyID: info.AuthorityKeyID,
		External:       true,
	}
	if err := s.st.CompleteCA(ctx, rec.ID, updated); err != nil {
		return nil, err
	}
	if in.MakeDefault {
		if err := s.st.SetDefaultCA(ctx, rec.ID); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, in.Actor, "ca.completed", rec.Name,
		fmt.Sprintf("serial=%s issuer=%q valid_until=%s",
			pki.SerialHex(cert.SerialNumber), info.Issuer, cert.NotAfter.Format("2006-01-02")))
	return s.st.GetCA(ctx, rec.ID)
}

// ImportCAInput describes an externally created authority being brought in.
type ImportCAInput struct {
	Name string `json:"name"`
	// CertPEM is the CA certificate. Required.
	CertPEM string `json:"cert_pem"`
	// KeyPEM is its private key. Supply it to let goca issue from this CA;
	// omit it to store the certificate as a read-only trust anchor.
	KeyPEM string `json:"key_pem"`
	// ChainPEM optionally carries issuers, imported as trust anchors.
	ChainPEM    string `json:"chain_pem"`
	MakeDefault bool   `json:"make_default"`
	Actor       string `json:"-"`
}

// ImportCA brings an external authority into goca. With a key it becomes a
// fully functional issuing CA; without one it is a trust anchor that completes
// chains and can be downloaded, but cannot sign.
func (s *Service) ImportCA(ctx context.Context, in ImportCAInput) (*store.CA, error) {
	if strings.TrimSpace(in.CertPEM) == "" {
		return nil, errors.New("a CA certificate is required")
	}
	certs, err := pki.ParseCertChainPEM([]byte(in.CertPEM))
	if err != nil {
		return nil, err
	}
	cert := certs[0]
	chainPEM := in.ChainPEM
	if len(certs) > 1 {
		for _, extra := range certs[1:] {
			chainPEM += string(pki.EncodeCertPEM(extra.Raw))
		}
	}
	if err := pki.ValidateCACertificate(cert); err != nil {
		return nil, err
	}

	info := pki.Describe(cert)
	if existing, err := s.st.FindCAByFingerprint(ctx, info.FingerprintSHA256); err == nil {
		return nil, fmt.Errorf("this certificate is already present as %q (id %d)",
			existing.Name, existing.ID)
	}

	keyEnc := ""
	keyType := info.KeyType
	if kp := strings.TrimSpace(in.KeyPEM); kp != "" {
		key, err := pki.ParsePrivateKeyPEM([]byte(kp))
		if err != nil {
			return nil, fmt.Errorf("parse the CA private key: %w", err)
		}
		if err := pki.MatchKeyToCertificate(key, cert); err != nil {
			return nil, err
		}
		keyEnc, err = s.box.EncryptString(normalizePEM(kp))
		if err != nil {
			return nil, fmt.Errorf("encrypt the imported CA key: %w", err)
		}
		keyType = string(pki.KeyTypeOf(key))
	}

	parentID, err := s.linkIssuer(ctx, cert, chainPEM, in.Actor)
	if err != nil {
		return nil, err
	}

	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = cert.Subject.CommonName
	}
	if name == "" {
		name = "Imported CA"
	}
	subject := pki.SubjectFromPKIX(cert.Subject)

	rec := &store.CA{
		Name:           s.uniqueName(ctx, name),
		Slug:           s.uniqueSlug(ctx, name),
		Subject:        info.Subject,
		SubjectJSON:    subject.JSON(),
		SerialHex:      pki.SerialHex(cert.SerialNumber),
		KeyType:        keyType,
		CertPEM:        string(pki.EncodeCertPEM(cert.Raw)),
		KeyEnc:         keyEnc,
		IsRoot:         pki.IsSelfSigned(cert),
		ParentID:       parentID,
		PathLen:        pki.PathLenOf(cert),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		Status:         store.StatusActive,
		Fingerprint:    info.FingerprintSHA256,
		SubjectKeyID:   info.SubjectKeyID,
		AuthorityKeyID: info.AuthorityKeyID,
		External:       true,
		CreatedBy:      in.Actor,
	}
	saved, err := s.st.CreateCA(ctx, rec)
	if err != nil {
		return nil, err
	}
	if in.MakeDefault {
		if keyEnc == "" {
			return nil, errors.New("a trust anchor has no private key and cannot be the default issuer")
		}
		if err := s.st.SetDefaultCA(ctx, saved.ID); err != nil {
			return nil, err
		}
		saved.IsDefault = true
	}

	kind := "trust anchor"
	if keyEnc != "" {
		kind = "issuing CA"
	}
	s.audit(ctx, in.Actor, "ca.import", saved.Name,
		fmt.Sprintf("%s serial=%s issuer=%q", kind, saved.SerialHex, info.Issuer))
	return saved, nil
}

// linkIssuer finds (or imports) the certificate's issuer and returns its ID.
// Certificates in chainPEM that are not yet known are stored as trust anchors,
// which is what makes a one-shot "import the pfSense chain" work.
func (s *Service) linkIssuer(ctx context.Context, cert *x509.Certificate, chainPEM, actor string) (*int64, error) {
	if pki.IsSelfSigned(cert) {
		return nil, nil
	}

	// Already stored?
	if id := s.findIssuerID(ctx, cert); id != nil {
		return id, nil
	}

	// Not stored, but perhaps supplied alongside. Import the chain from the
	// root down so each link can attach to its own parent.
	if strings.TrimSpace(chainPEM) != "" {
		chain, err := pki.ParseCertChainPEM([]byte(chainPEM))
		if err != nil {
			return nil, fmt.Errorf("parse the issuer chain: %w", err)
		}
		for i := len(chain) - 1; i >= 0; i-- {
			anchor := chain[i]
			info := pki.Describe(anchor)
			if _, err := s.st.FindCAByFingerprint(ctx, info.FingerprintSHA256); err == nil {
				continue // already imported
			}
			if !anchor.IsCA {
				continue // ignore any leaf that came along for the ride
			}
			parentID := s.findIssuerID(ctx, anchor)
			name := anchor.Subject.CommonName
			if name == "" {
				name = "Imported anchor"
			}
			subject := pki.SubjectFromPKIX(anchor.Subject)
			if _, err := s.st.CreateCA(ctx, &store.CA{
				Name:           s.uniqueName(ctx, name),
				Slug:           s.uniqueSlug(ctx, name),
				Subject:        info.Subject,
				SubjectJSON:    subject.JSON(),
				SerialHex:      pki.SerialHex(anchor.SerialNumber),
				KeyType:        info.KeyType,
				CertPEM:        string(pki.EncodeCertPEM(anchor.Raw)),
				IsRoot:         pki.IsSelfSigned(anchor),
				ParentID:       parentID,
				PathLen:        pki.PathLenOf(anchor),
				NotBefore:      anchor.NotBefore,
				NotAfter:       anchor.NotAfter,
				Status:         store.StatusActive,
				Fingerprint:    info.FingerprintSHA256,
				SubjectKeyID:   info.SubjectKeyID,
				AuthorityKeyID: info.AuthorityKeyID,
				External:       true,
				CreatedBy:      actor,
			}); err != nil {
				return nil, fmt.Errorf("import chain certificate %q: %w", info.Subject, err)
			}
			s.audit(ctx, actor, "ca.import_anchor", info.Subject, "from supplied chain")
		}
		if id := s.findIssuerID(ctx, cert); id != nil {
			return id, nil
		}
	}

	// The issuer is unknown. That is allowed - the certificate still works for
	// issuance - but chains this CA produces will be incomplete until the
	// issuer is imported, so say so rather than failing silently.
	return nil, nil
}

// findIssuerID resolves a certificate's issuer among the stored CAs, by
// authority key identifier first and by distinguished name as a fallback. The
// match is confirmed by verifying the signature.
func (s *Service) findIssuerID(ctx context.Context, cert *x509.Certificate) *int64 {
	verify := func(candidate *store.CA) *int64 {
		parsed, err := pki.ParseCertPEM([]byte(candidate.CertPEM))
		if err != nil {
			return nil
		}
		if err := pki.VerifyIssuedBy(cert, parsed); err != nil {
			return nil
		}
		id := candidate.ID
		return &id
	}
	if aki := hexColonsOf(cert.AuthorityKeyId); aki != "" {
		if c, err := s.st.FindCABySubjectKeyID(ctx, aki); err == nil {
			if id := verify(c); id != nil {
				return id
			}
		}
	}
	if c, err := s.st.FindCABySubject(ctx, pki.DNString(cert.Issuer)); err == nil {
		if id := verify(c); id != nil {
			return id
		}
	}
	// Last resort: try every stored CA. The set is small, and this catches
	// certificates whose AKI is absent and whose DN was rendered differently.
	all, err := s.st.ListCAs(ctx)
	if err != nil {
		return nil
	}
	for _, c := range all {
		if c.CertPEM == "" {
			continue
		}
		if id := verify(c); id != nil {
			return id
		}
	}
	return nil
}

// ChainComplete reports whether a CA chains all the way to a self-signed root
// that goca holds. An imported intermediate whose root was never uploaded
// answers false, and the UI nudges the operator to import it.
func (s *Service) ChainComplete(ctx context.Context, c *store.CA) bool {
	chain, err := s.CAChain(ctx, c)
	if err != nil || len(chain) == 0 {
		return false
	}
	return pki.IsSelfSigned(chain[len(chain)-1])
}

// uniqueName avoids the UNIQUE constraint on cas.name when importing a chain
// whose subjects collide with authorities already stored.
func (s *Service) uniqueName(ctx context.Context, name string) string {
	candidate := name
	for i := 2; i < 100; i++ {
		if _, err := s.st.GetCAByRef(ctx, candidate); errors.Is(err, store.ErrNotFound) {
			return candidate
		}
		candidate = fmt.Sprintf("%s (%d)", name, i)
	}
	return name
}

// hexColonsOf renders a key identifier the same way pki.Describe does, so the
// two can be compared.
func hexColonsOf(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}
