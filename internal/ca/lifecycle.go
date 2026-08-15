package ca

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// This file covers what happens to a certificate after it is issued: rotating
// it before expiry, and the several shapes revocation takes.

//
// ---------- renewal / rotation ----------
//

// RenewInput describes a rotation of an existing certificate.
type RenewInput struct {
	// Days overrides the validity of the replacement; zero keeps the original
	// certificate's span, falling back to the configured default.
	Days int `json:"days"`
	// SameKey reuses the stored private key instead of generating a new one.
	// Convenient when the key is pinned somewhere, but it means a compromised
	// key stays in play - a fresh key is the default for that reason.
	SameKey bool `json:"same_key"`
	// CARef moves the replacement to a different authority; empty keeps the
	// original issuer when it can still sign, otherwise the default is used.
	CARef string `json:"ca"`
	// KeyType changes the algorithm of the new key. Ignored with SameKey.
	KeyType string `json:"key_type"`
	// RevokeOld revokes the predecessor as superseded once the new one exists.
	RevokeOld bool `json:"revoke_old"`
	// StoreKey controls retention of the new key; defaults to whatever the
	// original did.
	StoreKey *bool  `json:"store_key"`
	Note     string `json:"note"`
	Actor    string `json:"-"`
}

// RenewResult carries the replacement certificate.
type RenewResult struct {
	Certificate   *store.Certificate `json:"certificate"`
	Previous      *store.Certificate `json:"previous"`
	PrivateKeyPEM string             `json:"private_key_pem,omitempty"`
	ChainPEM      string             `json:"chain_pem,omitempty"`
	RevokedOld    bool               `json:"revoked_old"`
}

// Renew issues a replacement for an existing certificate, carrying over its
// subject, SANs and profile. The original is left alone unless RevokeOld is
// set, so a deployment can be switched over before the old one is retired.
func (s *Service) Renew(ctx context.Context, id int64, in RenewInput) (*RenewResult, error) {
	old, err := s.st.GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}

	// Which authority signs the replacement.
	caRef := strings.TrimSpace(in.CARef)
	if caRef == "" {
		issuer, err := s.st.GetCA(ctx, old.CAID)
		if err == nil && checkCanIssue(issuer) == nil {
			caRef = fmt.Sprint(issuer.ID)
		}
	}

	days := in.Days
	if days <= 0 {
		// Keep the original span, so a 90-day certificate renews for 90 days.
		if span := int(old.NotAfter.Sub(old.NotBefore).Hours() / 24); span > 0 {
			days = span
		} else {
			days = s.cfg.CA.DefaultCertDays
		}
	}

	subject, err := subjectOf(old)
	if err != nil {
		return nil, err
	}

	storeKey := old.HasKey
	if in.StoreKey != nil {
		storeKey = *in.StoreKey
	}

	issue := IssueInput{
		CARef:    caRef,
		Subject:  subject,
		SANs:     old.SANs(),
		Profile:  old.Profile,
		Days:     days,
		StoreKey: &storeKey,
		Note:     firstNonEmpty(in.Note, old.Note),
		Actor:    in.Actor,
	}

	if in.SameKey {
		keyPEM, err := s.CertKeyPEM(ctx, old)
		if err != nil {
			return nil, fmt.Errorf("cannot reuse the existing key: %w", err)
		}
		key, err := pki.ParsePrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, err
		}
		sans, err := pki.ParseSANs(old.SANs())
		if err != nil {
			return nil, err
		}
		csrPEM, err := pki.CSRFromKey(key, pki.CSRRequest{Subject: subject, SANs: sans})
		if err != nil {
			return nil, fmt.Errorf("build a request for the existing key: %w", err)
		}
		issue.Mode = ModeCSR
		issue.CSRPEM = string(csrPEM)
		issue.KeyPEM = string(keyPEM)
		// A CSR carries its own SANs; passing them again would be redundant.
		issue.SANs = nil
	} else {
		issue.Mode = ModeGenerate
		issue.KeyType = firstNonEmpty(in.KeyType, old.KeyType, s.cfg.CA.DefaultKeyType)
	}

	res, err := s.Issue(ctx, issue)
	if err != nil {
		return nil, err
	}

	// Record the lineage so the history can be walked from either end.
	if err := s.st.SetRenewedFrom(ctx, res.Certificate.ID, old.ID); err != nil {
		return nil, err
	}
	res.Certificate.RenewedFrom = &old.ID

	out := &RenewResult{
		Certificate:   res.Certificate,
		Previous:      old,
		PrivateKeyPEM: res.PrivateKeyPEM,
		ChainPEM:      res.ChainPEM,
	}
	if in.RevokeOld && old.Status != store.StatusRevoked {
		if err := s.st.RevokeCertificate(ctx, old.ID, pki.ReasonSuperseded); err != nil {
			return nil, fmt.Errorf("the replacement was issued (serial %s) but revoking the old "+
				"certificate failed: %w", res.Certificate.SerialHex, err)
		}
		out.RevokedOld = true
	}

	s.audit(ctx, in.Actor, "cert.renew", old.CommonName,
		fmt.Sprintf("old_serial=%s new_serial=%s same_key=%t revoked_old=%t days=%d",
			old.SerialHex, res.Certificate.SerialHex, in.SameKey, out.RevokedOld, days))
	return out, nil
}

// RenewExpiring rotates every active certificate expiring within the given
// number of days. Failures are collected rather than aborting the batch, so one
// bad certificate cannot block the rest.
func (s *Service) RenewExpiring(ctx context.Context, withinDays int, in RenewInput) ([]*RenewResult, []error) {
	if withinDays <= 0 {
		withinDays = 30
	}
	due, _, err := s.st.SearchCertificates(ctx, store.CertFilter{
		ExpiringIn: withinDays,
		Limit:      1000,
		SortBy:     "not_after",
	})
	if err != nil {
		return nil, []error{err}
	}
	var (
		out  []*RenewResult
		errs []error
	)
	for _, c := range due {
		res, err := s.Renew(ctx, c.ID, in)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s (serial %s): %w", c.CommonName, c.SerialHex, err))
			continue
		}
		out = append(out, res)
	}
	return out, errs
}

// RenewalHistory returns the rotation chain a certificate belongs to, oldest
// first, following renewed_from links in both directions.
func (s *Service) RenewalHistory(ctx context.Context, c *store.Certificate) ([]*store.Certificate, error) {
	var back []*store.Certificate
	cur := c
	for i := 0; i < 64 && cur.RenewedFrom != nil; i++ {
		prev, err := s.st.GetCertificate(ctx, *cur.RenewedFrom)
		if err != nil {
			break
		}
		back = append([]*store.Certificate{prev}, back...)
		cur = prev
	}

	chain := append(back, c)

	next := c
	for i := 0; i < 64; i++ {
		successor, err := s.st.CertificateRenewedFrom(ctx, next.ID)
		if err != nil || successor == nil {
			break
		}
		chain = append(chain, successor)
		next = successor
	}
	return chain, nil
}

// subjectOf rebuilds a Subject from a stored certificate.
func subjectOf(c *store.Certificate) (pki.Subject, error) {
	cert, err := pki.ParseCertPEM([]byte(c.CertPEM))
	if err != nil {
		return pki.Subject{}, fmt.Errorf("parse the certificate being renewed: %w", err)
	}
	return pki.SubjectFromPKIX(cert.Subject), nil
}

//
// ---------- revocation ----------
//

// Hold revokes a certificate reversibly (RFC 5280 certificateHold). It appears
// on the CRL until released with Release.
func (s *Service) Hold(ctx context.Context, id int64, actor string) error {
	c, err := s.st.GetCertificate(ctx, id)
	if err != nil {
		return err
	}
	if c.Status == store.StatusRevoked {
		if c.OnHold() {
			return fmt.Errorf("%s is already on hold", c.CommonName)
		}
		return fmt.Errorf("%s is permanently revoked (%s) and cannot be put on hold",
			c.CommonName, pki.ReasonName(c.RevokeCode))
	}
	if err := s.st.RevokeCertificate(ctx, id, pki.ReasonCertificateHold); err != nil {
		return err
	}
	s.audit(ctx, actor, "cert.hold", c.CommonName, "serial="+c.SerialHex)
	return nil
}

// Release lifts a hold, returning the certificate to active use and dropping it
// from the next CRL. Only certificates on hold can be released; every other
// reason is a permanent statement.
func (s *Service) Release(ctx context.Context, id int64, actor string) error {
	c, err := s.st.GetCertificate(ctx, id)
	if err != nil {
		return err
	}
	if err := s.st.UnrevokeCertificate(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, "cert.release", c.CommonName, "serial="+c.SerialHex)
	return nil
}

// BulkRevokeInput selects certificates to revoke in one operation.
type BulkRevokeInput struct {
	// IDs revokes an explicit set.
	IDs []int64 `json:"ids"`
	// Filter revokes everything matching a search instead.
	Filter *store.CertFilter `json:"filter"`
	Reason int               `json:"reason"`
	Actor  string            `json:"-"`
}

// BulkRevokeResult reports what happened.
type BulkRevokeResult struct {
	Revoked []*store.Certificate `json:"revoked"`
	Skipped []string             `json:"skipped"`
	Errors  []string             `json:"errors"`
	// CAIDs lists the authorities whose CRLs are now stale.
	CAIDs []int64 `json:"affected_ca_ids"`
}

// BulkRevoke revokes many certificates at once, by explicit ID or by search
// filter. Already-revoked certificates are skipped rather than treated as
// errors, so the operation is safe to repeat.
func (s *Service) BulkRevoke(ctx context.Context, in BulkRevokeInput) (*BulkRevokeResult, error) {
	var targets []*store.Certificate

	for _, id := range in.IDs {
		c, err := s.st.GetCertificate(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", id, err)
		}
		targets = append(targets, c)
	}

	if in.Filter != nil {
		f := *in.Filter
		if f.Limit <= 0 {
			f.Limit = 1000
		}
		found, _, err := s.st.SearchCertificates(ctx, f)
		if err != nil {
			return nil, err
		}
		seen := map[int64]bool{}
		for _, c := range targets {
			seen[c.ID] = true
		}
		for _, c := range found {
			if !seen[c.ID] {
				targets = append(targets, c)
			}
		}
	}

	if len(targets) == 0 {
		return nil, errors.New("nothing matched; refusing to revoke an empty selection")
	}

	out := &BulkRevokeResult{}
	affected := map[int64]bool{}
	for _, c := range targets {
		if c.Status == store.StatusRevoked {
			out.Skipped = append(out.Skipped,
				fmt.Sprintf("%s (serial %s) was already revoked", c.CommonName, c.SerialHex))
			continue
		}
		if err := s.st.RevokeCertificate(ctx, c.ID, in.Reason); err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("%s: %v", c.CommonName, err))
			continue
		}
		out.Revoked = append(out.Revoked, c)
		affected[c.CAID] = true
	}
	for id := range affected {
		out.CAIDs = append(out.CAIDs, id)
	}

	s.audit(ctx, in.Actor, "cert.bulk_revoke", fmt.Sprintf("%d certificates", len(out.Revoked)),
		fmt.Sprintf("reason=%s skipped=%d errors=%d",
			pki.ReasonName(in.Reason), len(out.Skipped), len(out.Errors)))
	return out, nil
}

// RevokeCAResult reports the outcome of retiring an authority.
type RevokeCAResult struct {
	CA *store.CA `json:"ca"`
	// RevokedInParent is true when the CA's own certificate was revoked by its
	// parent, which is what makes the retirement visible to relying parties.
	RevokedInParent bool   `json:"revoked_in_parent"`
	ParentName      string `json:"parent_name,omitempty"`
	// Certificates counts the end-entity certificates revoked underneath it.
	Certificates int `json:"certificates_revoked"`
	// ChildCAs names subordinate authorities that were also retired.
	ChildCAs []string `json:"child_cas,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// RevokeCA retires an authority. It is disabled so nothing more can be issued
// from it; with cascade, every certificate it issued is revoked too, and with a
// parent that goca controls, its own certificate is revoked in the parent's CRL.
func (s *Service) RevokeCA(ctx context.Context, id int64, reason int, cascade bool, actor string) (*RevokeCAResult, error) {
	c, err := s.st.GetCA(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &RevokeCAResult{CA: c}

	// Stop new issuance first, so nothing slips through mid-operation.
	if err := s.st.SetCAStatus(ctx, id, store.StatusDisabled); err != nil {
		return nil, err
	}

	if cascade {
		certs, _, err := s.st.SearchCertificates(ctx, store.CertFilter{CAID: id, Limit: 10000})
		if err != nil {
			return nil, err
		}
		for _, cert := range certs {
			if cert.Status == store.StatusRevoked {
				continue
			}
			if err := s.st.RevokeCertificate(ctx, cert.ID, reason); err != nil {
				out.Warnings = append(out.Warnings,
					fmt.Sprintf("could not revoke %s: %v", cert.CommonName, err))
				continue
			}
			out.Certificates++
		}
		// Subordinate authorities beneath this one are retired as well.
		children, err := s.st.ChildCAs(ctx, id)
		if err == nil {
			for _, child := range children {
				sub, err := s.RevokeCA(ctx, child.ID, reason, true, actor)
				if err != nil {
					out.Warnings = append(out.Warnings,
						fmt.Sprintf("could not retire subordinate %s: %v", child.Name, err))
					continue
				}
				out.ChildCAs = append(out.ChildCAs, child.Name)
				out.Certificates += sub.Certificates
				out.ChildCAs = append(out.ChildCAs, sub.ChildCAs...)
			}
		}
	}

	// If the parent is one goca controls, put this CA on its CRL. That is the
	// only part of a retirement relying parties can actually observe.
	if c.ParentID != nil {
		parent, err := s.st.GetCA(ctx, *c.ParentID)
		if err == nil {
			out.ParentName = parent.Name
			if parent.HasKey() {
				if err := s.st.RecordCARevocation(ctx, parent.ID, c.SerialHex, reason); err != nil {
					out.Warnings = append(out.Warnings,
						fmt.Sprintf("could not add %s to the CRL of %s: %v", c.Name, parent.Name, err))
				} else {
					out.RevokedInParent = true
				}
			} else {
				out.Warnings = append(out.Warnings, fmt.Sprintf(
					"goca holds no private key for the issuer %q, so it cannot publish a CRL "+
						"listing this authority. Revoke it on the external authority as well",
					parent.Name))
			}
		}
	} else if !c.IsRoot {
		out.Warnings = append(out.Warnings,
			"this authority's issuer is not known to goca; revoke it on the external authority too")
	} else {
		out.Warnings = append(out.Warnings,
			"this is a root authority: nothing can revoke it, so remove it from your trust stores")
	}

	s.audit(ctx, actor, "ca.revoke", c.Name,
		fmt.Sprintf("reason=%s cascade=%t certificates=%d in_parent_crl=%t",
			pki.ReasonName(reason), cascade, out.Certificates, out.RevokedInParent))
	return out, nil
}
