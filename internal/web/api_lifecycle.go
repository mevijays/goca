package web

import (
	"net/http"
	"strings"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

//
// ---------- external CA integration ----------
//

// apiCASubordinateCSR generates a subordinate CA key and CSR for an external
// authority (pfSense and friends) to sign.
func (s *Server) apiCASubordinateCSR(w http.ResponseWriter, r *http.Request) error {
	var in ca.SubordinateCSRInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	in.Actor = currentUser(r).Username
	res, err := s.svc.CreateSubordinateCSR(r.Context(), in)
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusCreated, res)
	return nil
}

// apiCAImportSigned completes a pending subordinate CA.
func (s *Server) apiCAImportSigned(w http.ResponseWriter, r *http.Request) error {
	var in ca.CompleteSubordinateInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.CARef == "" {
		in.CARef = r.PathValue("id")
	}
	in.Actor = currentUser(r).Username
	c, err := s.svc.CompleteSubordinate(r.Context(), in)
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ca":             newCAResponse(c, describeOrNil(c.CertPEM)),
		"chain_complete": s.svc.ChainComplete(r.Context(), c),
	})
	return nil
}

// apiCAImport brings an externally created authority into goca.
func (s *Server) apiCAImport(w http.ResponseWriter, r *http.Request) error {
	var in ca.ImportCAInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	in.Actor = currentUser(r).Username
	c, err := s.svc.ImportCA(r.Context(), in)
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ca":             newCAResponse(c, describeOrNil(c.CertPEM)),
		"can_issue":      c.CanIssue(),
		"chain_complete": s.svc.ChainComplete(r.Context(), c),
	})
	return nil
}

// apiCAPending lists authorities awaiting an external signature.
func (s *Server) apiCAPending(w http.ResponseWriter, r *http.Request) error {
	pending, err := s.svc.Store().PendingCAs(r.Context())
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(pending))
	for _, c := range pending {
		out = append(out, map[string]any{"ca": newCAResponse(c, nil), "csr_pem": c.CSRPEM})
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": out, "count": len(out)})
	return nil
}

// apiCACSR returns the stored request of a pending authority.
func (s *Server) apiCACSR(w http.ResponseWriter, r *http.Request) error {
	id, err := s.pathCAID(r)
	if err != nil {
		return err
	}
	c, err := s.svc.GetCA(r.Context(), id)
	if err != nil {
		return err
	}
	if c.CSRPEM == "" {
		return notFound("this authority has no stored signing request")
	}
	writeJSON(w, http.StatusOK, map[string]string{"csr_pem": c.CSRPEM, "name": c.Name})
	return nil
}

// apiCARevoke retires an authority.
func (s *Server) apiCARevoke(w http.ResponseWriter, r *http.Request) error {
	id, err := s.pathCAID(r)
	if err != nil {
		return err
	}
	var body struct {
		Reason  any  `json:"reason"`
		Cascade bool `json:"cascade"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &body); err != nil {
			return err
		}
	}
	code, err := reasonCode(body.Reason, pki.ReasonCessationOfOperation)
	if err != nil {
		return err
	}
	res, err := s.svc.RevokeCA(r.Context(), id, code, body.Cascade, currentUser(r).Username)
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

//
// ---------- renewal ----------
//

// apiCertRenew issues a replacement for a certificate.
func (s *Server) apiCertRenew(w http.ResponseWriter, r *http.Request) error {
	c, err := s.apiLookupCert(r)
	if err != nil {
		return err
	}
	var in ca.RenewInput
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &in); err != nil {
			return err
		}
	}
	in.Actor = currentUser(r).Username
	res, err := s.svc.Renew(r.Context(), c.ID, in)
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"certificate": certResponse{
			Certificate: res.Certificate,
			CertPEM:     res.Certificate.CertPEM,
			SANs:        res.Certificate.SANs(),
		},
		"previous":        map[string]any{"id": res.Previous.ID, "serial": res.Previous.SerialHex},
		"private_key_pem": res.PrivateKeyPEM,
		"chain_pem":       res.ChainPEM,
		"revoked_old":     res.RevokedOld,
		"key_stored":      res.Certificate.HasKey,
	})
	return nil
}

// apiCertRenewExpiring rotates everything due within a window.
func (s *Server) apiCertRenewExpiring(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		WithinDays int  `json:"within_days"`
		SameKey    bool `json:"same_key"`
		RevokeOld  bool `json:"revoke_old"`
		Days       int  `json:"days"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &body); err != nil {
			return err
		}
	}
	if body.WithinDays <= 0 {
		body.WithinDays = 30
	}
	results, errs := s.svc.RenewExpiring(r.Context(), body.WithinDays, ca.RenewInput{
		Days:      body.Days,
		SameKey:   body.SameKey,
		RevokeOld: body.RevokeOld,
		Actor:     currentUser(r).Username,
	})
	renewed := make([]map[string]any, 0, len(results))
	for _, res := range results {
		renewed = append(renewed, map[string]any{
			"common_name":     res.Certificate.CommonName,
			"id":              res.Certificate.ID,
			"serial":          res.Certificate.SerialHex,
			"previous_serial": res.Previous.SerialHex,
			"not_after":       res.Certificate.NotAfter,
		})
	}
	failed := make([]string, 0, len(errs))
	for _, e := range errs {
		failed = append(failed, e.Error())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"renewed": renewed, "count": len(renewed), "errors": failed,
	})
	return nil
}

// apiCertHistory returns the rotation chain a certificate belongs to.
func (s *Server) apiCertHistory(w http.ResponseWriter, r *http.Request) error {
	c, err := s.apiLookupCert(r)
	if err != nil {
		return err
	}
	chain, err := s.svc.RenewalHistory(r.Context(), c)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": chain, "current_id": c.ID})
	return nil
}

//
// ---------- revocation variants ----------
//

// apiCertHold suspends a certificate reversibly.
func (s *Server) apiCertHold(w http.ResponseWriter, r *http.Request) error {
	c, err := s.apiLookupCert(r)
	if err != nil {
		return err
	}
	if err := s.svc.Hold(r.Context(), c.ID, currentUser(r).Username); err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "on_hold", "reversible": true, "serial": c.SerialHex,
	})
	return nil
}

// apiCertRelease lifts a hold.
func (s *Server) apiCertRelease(w http.ResponseWriter, r *http.Request) error {
	c, err := s.apiLookupCert(r)
	if err != nil {
		return err
	}
	if err := s.svc.Release(r.Context(), c.ID, currentUser(r).Username); err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "active", "serial": c.SerialHex})
	return nil
}

// apiCertBulkRevoke revokes many certificates in one call.
func (s *Server) apiCertBulkRevoke(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		IDs     []int64 `json:"ids"`
		Query   string  `json:"query"`
		CAID    int64   `json:"ca_id"`
		Profile string  `json:"profile"`
		Status  string  `json:"status"`
		Reason  any     `json:"reason"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	code, err := reasonCode(body.Reason, pki.ReasonUnspecified)
	if err != nil {
		return err
	}

	in := ca.BulkRevokeInput{IDs: body.IDs, Reason: code, Actor: currentUser(r).Username}
	if body.Query != "" || body.CAID > 0 || body.Profile != "" || body.Status != "" {
		in.Filter = &store.CertFilter{
			Query:   body.Query,
			CAID:    body.CAID,
			Profile: body.Profile,
			Status:  body.Status,
			Limit:   1000,
		}
	}
	if len(in.IDs) == 0 && in.Filter == nil {
		return badRequest("supply ids, or at least one of query, ca_id, profile or status; " +
			"an unfiltered bulk revoke is refused")
	}

	res, err := s.svc.BulkRevoke(r.Context(), in)
	if err != nil {
		return badRequestFrom(err)
	}
	revoked := make([]map[string]any, 0, len(res.Revoked))
	for _, c := range res.Revoked {
		revoked = append(revoked, map[string]any{
			"id": c.ID, "common_name": c.CommonName, "serial": c.SerialHex})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revoked":         revoked,
		"count":           len(revoked),
		"skipped":         res.Skipped,
		"errors":          res.Errors,
		"affected_ca_ids": res.CAIDs,
		"reason":          pki.ReasonName(code),
	})
	return nil
}

// reasonCode accepts a numeric or named revocation reason from JSON.
func reasonCode(v any, def int) (int, error) {
	switch t := v.(type) {
	case nil:
		return def, nil
	case float64:
		return int(t), nil
	case string:
		if strings.TrimSpace(t) == "" {
			return def, nil
		}
		code, err := pki.ParseReason(t)
		if err != nil {
			return 0, badRequestFrom(err)
		}
		return code, nil
	}
	return 0, badRequest("reason must be a number or a name such as \"keyCompromise\"")
}
