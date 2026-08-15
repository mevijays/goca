package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

//
// ---------- external CA integration ----------
//

// caImportForm mirrors the import page so a failed submit can be re-rendered.
type caImportForm struct {
	Mode                                         string // request | with-key | anchor
	Name                                         string
	CommonName, Organization, OrganizationalUnit string
	Country, Province, Locality                  string
	KeyType                                      string
	CertPEM, KeyPEM, ChainPEM                    string
	MakeDefault                                  bool
}

func (s *Server) handleCAImportForm(w http.ResponseWriter, r *http.Request) {
	pending, _ := s.svc.Store().PendingCAs(r.Context())
	form := caImportForm{
		Mode:    firstNonEmpty(r.URL.Query().Get("mode"), "request"),
		KeyType: firstNonEmpty(s.cfg.CA.DefaultKeyType, string(pki.KeyRSA4096)),
	}
	s.render(w, r, "ca_import.html", viewData{
		Title: "Connect an external CA",
		Nav:   "cas",
		Data:  map[string]any{"Form": form, "Pending": pending},
	})
}

func (s *Server) handleCAImportSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		// Not multipart: a plain form post is fine too.
		if err := r.ParseForm(); err != nil {
			s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
			return
		}
	}

	form := caImportForm{
		Mode:               firstNonEmpty(r.FormValue("mode"), "request"),
		Name:               strings.TrimSpace(r.FormValue("name")),
		CommonName:         strings.TrimSpace(r.FormValue("common_name")),
		Organization:       strings.TrimSpace(r.FormValue("organization")),
		OrganizationalUnit: strings.TrimSpace(r.FormValue("organizational_unit")),
		Country:            strings.TrimSpace(r.FormValue("country")),
		Province:           strings.TrimSpace(r.FormValue("province")),
		Locality:           strings.TrimSpace(r.FormValue("locality")),
		KeyType:            r.FormValue("key_type"),
		CertPEM:            strings.TrimSpace(r.FormValue("cert_pem")),
		KeyPEM:             strings.TrimSpace(r.FormValue("key_pem")),
		ChainPEM:           strings.TrimSpace(r.FormValue("chain_pem")),
		MakeDefault:        r.FormValue("make_default") == "1",
	}
	// Uploaded files win over pasted text, so either route works.
	form.CertPEM = firstNonEmpty(uploadedFile(r, "cert_file"), form.CertPEM)
	form.KeyPEM = firstNonEmpty(uploadedFile(r, "key_file"), form.KeyPEM)
	form.ChainPEM = firstNonEmpty(uploadedFile(r, "chain_file"), form.ChainPEM)

	fail := func(err error) {
		pending, _ := s.svc.Store().PendingCAs(r.Context())
		s.render(w, r, "ca_import.html", viewData{
			Title: "Connect an external CA",
			Nav:   "cas",
			Data:  map[string]any{"Form": form, "Pending": pending, "Error": err.Error()},
		})
	}

	actor := currentUser(r).Username
	switch form.Mode {
	case "request":
		res, err := s.svc.CreateSubordinateCSR(r.Context(), ca.SubordinateCSRInput{
			Name: form.Name,
			Subject: pki.Subject{
				CommonName:         form.CommonName,
				Organization:       form.Organization,
				OrganizationalUnit: form.OrganizationalUnit,
				Country:            form.Country,
				Province:           form.Province,
				Locality:           form.Locality,
			},
			KeyType: form.KeyType,
			Actor:   actor,
		})
		if err != nil {
			fail(err)
			return
		}
		s.flash(w, r, "success",
			fmt.Sprintf("Request created for %q. Send the CSR below to your external authority, "+
				"then import the signed certificate here.", res.CA.Name))
		http.Redirect(w, r, fmt.Sprintf("/cas/%d", res.CA.ID), http.StatusSeeOther)

	case "with-key", "anchor":
		in := ca.ImportCAInput{
			Name:        form.Name,
			CertPEM:     form.CertPEM,
			ChainPEM:    form.ChainPEM,
			MakeDefault: form.MakeDefault,
			Actor:       actor,
		}
		if form.Mode == "with-key" {
			if form.KeyPEM == "" {
				fail(fmt.Errorf("a private key is required to import an issuing CA; " +
					"choose \"trust anchor\" to import the certificate alone"))
				return
			}
			in.KeyPEM = form.KeyPEM
		}
		c, err := s.svc.ImportCA(r.Context(), in)
		if err != nil {
			fail(err)
			return
		}
		msg := fmt.Sprintf("Imported %q as a trust anchor. It completes chains but cannot issue.", c.Name)
		if c.HasKey() {
			msg = fmt.Sprintf("Imported %q. It can issue certificates now.", c.Name)
		}
		s.flash(w, r, "success", msg)
		http.Redirect(w, r, fmt.Sprintf("/cas/%d", c.ID), http.StatusSeeOther)

	default:
		fail(fmt.Errorf("unknown import mode %q", form.Mode))
	}
}

// handleCACompleteSigned takes the signed certificate for a pending authority.
func (s *Server) handleCACompleteSigned(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCA(w, r)
	if !ok {
		return
	}
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		if err := r.ParseForm(); err != nil {
			s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
			return
		}
	}
	certPEM := firstNonEmpty(uploadedFile(r, "cert_file"), strings.TrimSpace(r.FormValue("cert_pem")))
	chainPEM := firstNonEmpty(uploadedFile(r, "chain_file"), strings.TrimSpace(r.FormValue("chain_pem")))

	updated, err := s.svc.CompleteSubordinate(r.Context(), ca.CompleteSubordinateInput{
		CARef:       fmt.Sprint(c.ID),
		CertPEM:     certPEM,
		ChainPEM:    chainPEM,
		MakeDefault: r.FormValue("make_default") == "1",
		Actor:       currentUser(r).Username,
	})
	if err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, fmt.Sprintf("/cas/%d", c.ID), http.StatusSeeOther)
		return
	}
	msg := fmt.Sprintf("%q is active and can issue certificates.", updated.Name)
	if !s.svc.ChainComplete(r.Context(), updated) {
		msg += " Its issuer is not yet known to goca, so chains will be incomplete — " +
			"import the external authority's certificate as a trust anchor."
	}
	s.flash(w, r, "success", msg)
	http.Redirect(w, r, fmt.Sprintf("/cas/%d", updated.ID), http.StatusSeeOther)
}

// handleCARevoke retires an authority from the portal.
func (s *Server) handleCARevoke(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCA(w, r)
	if !ok {
		return
	}
	code := atoiDefault(r.FormValue("reason"), pki.ReasonCessationOfOperation)
	cascade := r.FormValue("cascade") == "1"

	res, err := s.svc.RevokeCA(r.Context(), c.ID, code, cascade, currentUser(r).Username)
	if err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, fmt.Sprintf("/cas/%d", c.ID), http.StatusSeeOther)
		return
	}
	msg := fmt.Sprintf("%q retired: issuance disabled", c.Name)
	if cascade {
		msg += fmt.Sprintf(", %d certificate(s) revoked", res.Certificates)
	}
	if res.RevokedInParent {
		msg += fmt.Sprintf(", added to the CRL of %s", res.ParentName)
	}
	if len(res.Warnings) > 0 {
		msg += ". " + strings.Join(res.Warnings, " ")
	}
	s.flash(w, r, "success", msg+".")
	http.Redirect(w, r, fmt.Sprintf("/cas/%d", c.ID), http.StatusSeeOther)
}

//
// ---------- certificate lifecycle ----------
//

func (s *Server) handleCertRenew(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	in := ca.RenewInput{
		Days:      atoiDefault(r.FormValue("days"), 0),
		SameKey:   r.FormValue("same_key") == "1",
		RevokeOld: r.FormValue("revoke_old") == "1",
		Actor:     currentUser(r).Username,
	}
	res, err := s.svc.Renew(r.Context(), c.ID, in)
	if err != nil {
		s.flash(w, r, "error", "Renewal failed: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/certificates/%d", c.ID), http.StatusSeeOther)
		return
	}

	msg := fmt.Sprintf("Renewed: new serial %s, valid until %s.",
		res.Certificate.SerialHex, res.Certificate.NotAfter.Format("2006-01-02"))
	if res.RevokedOld {
		msg += " The previous certificate was revoked as superseded."
	} else {
		msg += " The previous certificate is still valid — revoke it once the new one is deployed."
	}
	s.flash(w, r, "success", msg)

	// When the key was not retained, this render is the only chance to save it.
	if res.PrivateKeyPEM != "" && !res.Certificate.HasKey {
		s.renderCertDetail(w, r, res.Certificate, "", res.PrivateKeyPEM)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/certificates/%d", res.Certificate.ID), http.StatusSeeOther)
}

func (s *Server) handleCertHold(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	if err := s.svc.Hold(r.Context(), c.ID, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", fmt.Sprintf(
			"%s is on hold. It appears on the CRL, and the hold can be lifted.", c.CommonName))
	}
	http.Redirect(w, r, fmt.Sprintf("/certificates/%d", c.ID), http.StatusSeeOther)
}

func (s *Server) handleCertRelease(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	if err := s.svc.Release(r.Context(), c.ID, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", fmt.Sprintf(
			"%s is active again. Regenerate the CRL to publish the change.", c.CommonName))
	}
	http.Redirect(w, r, fmt.Sprintf("/certificates/%d", c.ID), http.StatusSeeOther)
}

// handleCertBulkAction applies revoke, hold, release or renew to a selection
// made with the checkboxes on the certificate list.
func (s *Server) handleCertBulkAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	action := r.FormValue("action")
	ids := r.Form["selected"]
	if len(ids) == 0 {
		s.flash(w, r, "error", "Select at least one certificate first.")
		http.Redirect(w, r, redirectBack(r, "/certificates"), http.StatusSeeOther)
		return
	}

	user := currentUser(r)
	var idList []int64
	for _, raw := range ids {
		id := int64(atoiDefault(raw, 0))
		if id == 0 {
			continue
		}
		// Non-admins may only touch their own certificates.
		if !user.IsAdmin() {
			c, err := s.svc.GetCertificate(r.Context(), id)
			if err != nil || (c.RequestedBy != "" && c.RequestedBy != user.Username) {
				continue
			}
		}
		idList = append(idList, id)
	}
	if len(idList) == 0 {
		s.flash(w, r, "error", "None of the selected certificates are yours to change.")
		http.Redirect(w, r, redirectBack(r, "/certificates"), http.StatusSeeOther)
		return
	}

	switch action {
	case "revoke":
		reason := atoiDefault(r.FormValue("reason"), pki.ReasonUnspecified)
		res, err := s.svc.BulkRevoke(r.Context(), ca.BulkRevokeInput{
			IDs: idList, Reason: reason, Actor: user.Username})
		if err != nil {
			s.flash(w, r, "error", err.Error())
			break
		}
		msg := fmt.Sprintf("Revoked %d certificate(s) as %s.", len(res.Revoked), pki.ReasonName(reason))
		if len(res.Skipped) > 0 {
			msg += fmt.Sprintf(" %d were already revoked.", len(res.Skipped))
		}
		s.flash(w, r, "success", msg)

	case "hold":
		n, failed := 0, 0
		for _, id := range idList {
			if err := s.svc.Hold(r.Context(), id, user.Username); err != nil {
				failed++
				continue
			}
			n++
		}
		s.flash(w, r, "success", fmt.Sprintf("%d certificate(s) placed on hold, %d skipped.", n, failed))

	case "release":
		n, failed := 0, 0
		for _, id := range idList {
			if err := s.svc.Release(r.Context(), id, user.Username); err != nil {
				failed++
				continue
			}
			n++
		}
		s.flash(w, r, "success", fmt.Sprintf("%d certificate(s) released, %d skipped.", n, failed))

	case "renew":
		n := 0
		var errs []string
		for _, id := range idList {
			if _, err := s.svc.Renew(r.Context(), id, ca.RenewInput{Actor: user.Username}); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			n++
		}
		msg := fmt.Sprintf("Renewed %d certificate(s).", n)
		if len(errs) > 0 {
			msg += fmt.Sprintf(" %d failed: %s", len(errs), errs[0])
		}
		s.flash(w, r, "success", msg)

	default:
		s.flash(w, r, "error", "Unknown bulk action "+action)
	}

	http.Redirect(w, r, redirectBack(r, "/certificates"), http.StatusSeeOther)
}

//
// ---------- helpers ----------
//

// uploadedFile returns the contents of a multipart upload, or "" when absent.
func uploadedFile(r *http.Request, field string) string {
	if r.MultipartForm == nil {
		return ""
	}
	files := r.MultipartForm.File[field]
	if len(files) == 0 {
		return ""
	}
	f, err := files[0].Open()
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	n, _ := f.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

// redirectBack returns the referring path when it is local, else a fallback.
func redirectBack(r *http.Request, fallback string) string {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return fallback
	}
	// Only same-origin relative paths, never an absolute URL from elsewhere.
	if i := strings.Index(ref, "://"); i >= 0 {
		rest := ref[i+3:]
		slash := strings.Index(rest, "/")
		if slash < 0 {
			return fallback
		}
		ref = rest[slash:]
	}
	if !strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "//") {
		return fallback
	}
	return ref
}

// caIssuanceState summarises why a CA can or cannot issue, for the UI.
func caIssuanceState(c *store.CA) (canIssue bool, reason string) {
	switch {
	case c.Pending():
		return false, "waiting for an externally signed certificate"
	case !c.HasKey():
		return false, "trust anchor — goca holds no private key for it"
	case c.Status != store.StatusActive:
		return false, "issuance is " + c.Status
	case c.Expired():
		return false, "the CA certificate has expired"
	}
	return true, ""
}
