package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

const pageSize = 25

//
// ---------- dashboard ----------
//

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats, err := s.svc.Store().Stats(ctx)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	cas, _ := s.svc.ListCAs(ctx)
	recent, _, _ := s.svc.Search(ctx, store.CertFilter{Limit: 10, SortBy: "created_at", SortDesc: true})
	expiring, _, _ := s.svc.Search(ctx, store.CertFilter{ExpiringIn: 30, Limit: 10, SortBy: "not_after"})

	s.render(w, r, "dashboard.html", viewData{
		Title: "Dashboard",
		Nav:   "dashboard",
		Data: map[string]any{
			"Stats":    stats,
			"CAs":      cas,
			"Recent":   recent,
			"Expiring": expiring,
			"HasCA":    len(cas) > 0,
		},
	})
}

//
// ---------- certificate authorities ----------
//

func (s *Server) handleCAList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cas, err := s.svc.ListCAs(ctx)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	counts := map[int64]int{}
	var pending []*store.CA
	for _, c := range cas {
		_, n, _ := s.svc.Search(ctx, store.CertFilter{CAID: c.ID, Limit: 1})
		counts[c.ID] = n
		if c.Pending() {
			pending = append(pending, c)
		}
	}
	s.render(w, r, "cas.html", viewData{
		Title: "Certificate authorities",
		Nav:   "cas",
		Data:  map[string]any{"CAs": cas, "Counts": counts, "Pending": pending},
	})
}

// caFormValues mirrors the CA wizard so a failed submit can be re-rendered.
type caFormValues struct {
	Kind, Parent, Name                           string
	CommonName, Organization, OrganizationalUnit string
	Country, Province, Locality                  string
	KeyType                                      string
	Days, PathLen                                int
	CRLURLs, OCSPURLs, PermittedDNS              string
	MakeDefault                                  bool
}

func (s *Server) handleCANewForm(w http.ResponseWriter, r *http.Request) {
	cas, _ := s.svc.ListCAs(r.Context())
	form := caFormValues{
		Kind:        "root",
		KeyType:     s.cfg.CA.DefaultKeyType,
		Days:        s.cfg.CA.DefaultCADays,
		PathLen:     1,
		MakeDefault: len(cas) == 0,
	}
	if form.KeyType == "" {
		form.KeyType = string(pki.KeyRSA4096)
	}
	if s.cfg.Server.BaseURL != "" {
		form.CRLURLs = "" // filled in by the placeholder; left blank to stay optional
	}
	s.render(w, r, "ca_new.html", viewData{
		Title: "New authority",
		Nav:   "cas",
		Data:  map[string]any{"CAs": cas, "Form": form},
	})
}

func (s *Server) handleCACreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	form := caFormValues{
		Kind:               r.FormValue("ca_kind"),
		Parent:             r.FormValue("parent"),
		Name:               strings.TrimSpace(r.FormValue("name")),
		CommonName:         strings.TrimSpace(r.FormValue("common_name")),
		Organization:       strings.TrimSpace(r.FormValue("organization")),
		OrganizationalUnit: strings.TrimSpace(r.FormValue("organizational_unit")),
		Country:            strings.TrimSpace(r.FormValue("country")),
		Province:           strings.TrimSpace(r.FormValue("province")),
		Locality:           strings.TrimSpace(r.FormValue("locality")),
		KeyType:            r.FormValue("key_type"),
		Days:               atoiDefault(r.FormValue("days"), s.cfg.CA.DefaultCADays),
		PathLen:            atoiDefault(r.FormValue("path_len"), 1),
		CRLURLs:            r.FormValue("crl_urls"),
		OCSPURLs:           r.FormValue("ocsp_urls"),
		PermittedDNS:       r.FormValue("permitted_dns"),
		MakeDefault:        r.FormValue("make_default") == "1",
	}

	in := ca.CreateCAInput{
		Name: form.Name,
		Subject: pki.Subject{
			CommonName:         form.CommonName,
			Organization:       form.Organization,
			OrganizationalUnit: form.OrganizationalUnit,
			Country:            form.Country,
			Province:           form.Province,
			Locality:           form.Locality,
		},
		KeyType:       form.KeyType,
		Days:          form.Days,
		PathLen:       form.PathLen,
		CRLDistPoints: splitCSV(form.CRLURLs),
		OCSPServers:   splitCSV(form.OCSPURLs),
		PermittedDNS:  splitCSV(form.PermittedDNS),
		MakeDefault:   form.MakeDefault,
		Actor:         currentUser(r).Username,
	}
	if form.Kind == "intermediate" {
		in.ParentRef = form.Parent
	}

	created, err := s.svc.CreateCA(r.Context(), in)
	if err != nil {
		cas, _ := s.svc.ListCAs(r.Context())
		s.render(w, r, "ca_new.html", viewData{
			Title: "New authority",
			Nav:   "cas",
			Data:  map[string]any{"CAs": cas, "Form": form, "Error": err.Error()},
		})
		return
	}
	s.flash(w, r, "success", fmt.Sprintf("Authority %q created.", created.Name))
	http.Redirect(w, r, fmt.Sprintf("/cas/%d", created.ID), http.StatusSeeOther)
}

func (s *Server) handleCADetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, ok := s.lookupCA(w, r)
	if !ok {
		return
	}

	// A pending authority has no certificate yet, so there is nothing to parse.
	var info pki.CertInfo
	if c.CertPEM != "" {
		parsed, err := pki.ParseCertPEM([]byte(c.CertPEM))
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "Corrupt certificate", err.Error())
			return
		}
		info = pki.Describe(parsed)
	}

	certs, total, _ := s.svc.Search(ctx, store.CertFilter{CAID: c.ID, Limit: 10, SortBy: "created_at", SortDesc: true})
	_, revoked, _ := s.svc.Search(ctx, store.CertFilter{CAID: c.ID, Status: store.StatusRevoked, Limit: 1})

	var parent *store.CA
	if c.ParentID != nil {
		parent, _ = s.svc.GetCA(ctx, *c.ParentID)
	}
	canIssue, blocked := caIssuanceState(c)

	s.render(w, r, "ca_detail.html", viewData{
		Title: c.Name,
		Nav:   "cas",
		Data: map[string]any{
			"CA":                 c,
			"Info":               info,
			"Certs":              certs,
			"IssuedCount":        total,
			"RevokedCount":       revoked,
			"Parent":             parent,
			"CanIssue":           canIssue,
			"IssueBlockedReason": blocked,
			"ChainComplete":      c.CertPEM != "" && s.svc.ChainComplete(ctx, c),
		},
	})
}

func (s *Server) handleCASetDefault(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCA(w, r)
	if !ok {
		return
	}
	if err := s.svc.SetDefaultCA(r.Context(), c.ID, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", fmt.Sprintf("%q is now the default issuing authority.", c.Name))
	}
	http.Redirect(w, r, fmt.Sprintf("/cas/%d", c.ID), http.StatusSeeOther)
}

func (s *Server) handleCASetStatus(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCA(w, r)
	if !ok {
		return
	}
	status := r.FormValue("status")
	if err := s.svc.SetCAStatus(r.Context(), c.ID, status, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", fmt.Sprintf("%q is now %s.", c.Name, status))
	}
	http.Redirect(w, r, fmt.Sprintf("/cas/%d", c.ID), http.StatusSeeOther)
}

func (s *Server) handleCADelete(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCA(w, r)
	if !ok {
		return
	}
	if err := s.svc.DeleteCA(r.Context(), c.ID, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, fmt.Sprintf("/cas/%d", c.ID), http.StatusSeeOther)
		return
	}
	s.flash(w, r, "success", fmt.Sprintf("Authority %q deleted.", c.Name))
	http.Redirect(w, r, "/cas", http.StatusSeeOther)
}

func (s *Server) handleCAGenerateCRL(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCA(w, r)
	if !ok {
		return
	}
	if _, _, err := s.svc.GenerateCRL(r.Context(), c.ID, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", "CRL generation failed: "+err.Error())
	} else {
		s.flash(w, r, "success", "A fresh CRL has been generated.")
	}
	http.Redirect(w, r, fmt.Sprintf("/cas/%d", c.ID), http.StatusSeeOther)
}

//
// ---------- certificates ----------
//

func (s *Server) handleCertList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	page := atoiDefault(q.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	sort := q.Get("sort")
	if sort == "" {
		sort = "created_at"
	}
	filter := store.CertFilter{
		Query:      strings.TrimSpace(q.Get("q")),
		CAID:       int64(atoiDefault(q.Get("ca"), 0)),
		Status:     q.Get("status"),
		ExpiringIn: atoiDefault(q.Get("expiring"), 0),
		Limit:      pageSize,
		Offset:     (page - 1) * pageSize,
		SortBy:     sort,
		SortDesc:   sort == "created_at",
	}
	// Non-admins only see what they requested themselves.
	if !currentUser(r).IsAdmin() {
		filter.RequestedBy = currentUser(r).Username
	}

	certs, total, err := s.svc.Search(ctx, filter)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Search failed", err.Error())
		return
	}
	cas, _ := s.svc.ListCAs(ctx)

	pageURL := url.Values{}
	for _, k := range []string{"q", "ca", "status", "expiring", "sort"} {
		if v := q.Get(k); v != "" {
			pageURL.Set(k, v)
		}
	}
	pages := (total + pageSize - 1) / pageSize

	s.render(w, r, "certs.html", viewData{
		Title: "Certificates",
		Nav:   "certs",
		Data: map[string]any{
			"Certs":    certs,
			"Total":    total,
			"CAs":      cas,
			"Filter":   filter,
			"Sort":     sort,
			"Page":     page,
			"Pages":    pages,
			"PageURL":  "/certificates?" + pageURL.Encode(),
			"Filtered": len(pageURL) > 0,
		},
	})
}

// certFormValues mirrors the request form.
type certFormValues struct {
	Mode, CA, Profile                            string
	CommonName, Organization, OrganizationalUnit string
	Country, Province, Locality                  string
	SANs, KeyType, Note                          string
	CSRPEM, KeyPEM                               string
	Days                                         int
	StoreKey                                     bool
}

func (s *Server) handleCertNewForm(w http.ResponseWriter, r *http.Request) {
	cas, _ := s.svc.ListCAs(r.Context())
	form := certFormValues{
		Mode:     firstNonEmpty(r.URL.Query().Get("mode"), "generate"),
		CA:       r.URL.Query().Get("ca"),
		Profile:  string(pki.ProfileServer),
		KeyType:  firstNonEmpty(s.cfg.CA.DefaultKeyType, string(pki.KeyRSA2048)),
		Days:     s.cfg.CA.DefaultCertDays,
		StoreKey: true,
	}
	if form.CA == "" {
		if def, err := s.svc.ResolveCA(r.Context(), ""); err == nil {
			form.CA = fmt.Sprint(def.ID)
		}
	}
	s.render(w, r, "cert_new.html", viewData{
		Title: "Request a certificate",
		Nav:   "request",
		Data:  map[string]any{"CAs": cas, "Form": form},
	})
}

func (s *Server) handleCertCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	form := certFormValues{
		Mode:               firstNonEmpty(r.FormValue("mode"), "generate"),
		CA:                 r.FormValue("ca"),
		Profile:            r.FormValue("profile"),
		CommonName:         strings.TrimSpace(r.FormValue("common_name")),
		Organization:       strings.TrimSpace(r.FormValue("organization")),
		OrganizationalUnit: strings.TrimSpace(r.FormValue("organizational_unit")),
		Country:            strings.TrimSpace(r.FormValue("country")),
		Province:           strings.TrimSpace(r.FormValue("province")),
		Locality:           strings.TrimSpace(r.FormValue("locality")),
		SANs:               r.FormValue("sans"),
		KeyType:            r.FormValue("key_type"),
		Note:               strings.TrimSpace(r.FormValue("note")),
		CSRPEM:             strings.TrimSpace(r.FormValue("csr_pem")),
		KeyPEM:             strings.TrimSpace(r.FormValue("key_pem")),
		Days:               atoiDefault(r.FormValue("days"), s.cfg.CA.DefaultCertDays),
		StoreKey:           r.FormValue("store_key") == "1",
	}

	storeKey := form.StoreKey
	in := ca.IssueInput{
		CARef: form.CA,
		Mode:  ca.IssueMode(form.Mode),
		Subject: pki.Subject{
			CommonName:         form.CommonName,
			Organization:       form.Organization,
			OrganizationalUnit: form.OrganizationalUnit,
			Country:            form.Country,
			Province:           form.Province,
			Locality:           form.Locality,
		},
		SANs:     splitCSV(form.SANs),
		KeyType:  form.KeyType,
		Profile:  form.Profile,
		Days:     form.Days,
		CSRPEM:   form.CSRPEM,
		KeyPEM:   form.KeyPEM,
		StoreKey: &storeKey,
		Note:     form.Note,
		Actor:    currentUser(r).Username,
	}

	res, err := s.svc.Issue(r.Context(), in)
	if err != nil {
		cas, _ := s.svc.ListCAs(r.Context())
		s.render(w, r, "cert_new.html", viewData{
			Title: "Request a certificate",
			Nav:   "request",
			Data:  map[string]any{"CAs": cas, "Form": form, "Error": err.Error()},
		})
		return
	}

	// When the key was generated but deliberately not stored, this render is
	// the only chance the requester has to save it.
	if res.PrivateKeyPEM != "" && !res.Certificate.HasKey {
		s.renderCertDetail(w, r, res.Certificate, "", res.PrivateKeyPEM)
		return
	}
	s.flash(w, r, "success",
		fmt.Sprintf("Certificate issued for %s (serial %s).", res.Certificate.CommonName, res.Certificate.SerialHex))
	http.Redirect(w, r, fmt.Sprintf("/certificates/%d", res.Certificate.ID), http.StatusSeeOther)
}

func (s *Server) handleCertDetail(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	s.renderCertDetail(w, r, c, "", "")
}

func (s *Server) renderCertDetail(w http.ResponseWriter, r *http.Request, c *store.Certificate, newKey, keyOnce string) {
	info, err := s.svc.Describe(c)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Corrupt certificate", err.Error())
		return
	}
	profile, _ := pki.ParseProfile(c.Profile)

	// Show the rotation chain only when there is more than this certificate in it.
	var history []*store.Certificate
	if chain, err := s.svc.RenewalHistory(r.Context(), c); err == nil && len(chain) > 1 {
		history = chain
	}
	renewDays := int(c.NotAfter.Sub(c.NotBefore).Hours() / 24)
	if renewDays <= 0 {
		renewDays = s.cfg.CA.DefaultCertDays
	}

	s.render(w, r, "cert_detail.html", viewData{
		Title: c.CommonName,
		Nav:   "certs",
		Data: map[string]any{
			"Cert":            c,
			"Info":            info,
			"ProfileEnum":     profile,
			"NewKey":          newKey,
			"NewKeyNotStored": keyOnce,
			"History":         history,
			"RenewDays":       renewDays,
		},
	})
}

func (s *Server) handleCertRevoke(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	reason := atoiDefault(r.FormValue("reason"), pki.ReasonUnspecified)
	if err := s.svc.Revoke(r.Context(), c.ID, reason, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success",
			fmt.Sprintf("%s revoked (%s). Regenerate the CRL to publish it.", c.CommonName, pki.ReasonName(reason)))
	}
	http.Redirect(w, r, fmt.Sprintf("/certificates/%d", c.ID), http.StatusSeeOther)
}

func (s *Server) handleCertDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	if err := s.svc.Store().DeleteCertificate(r.Context(), c.ID); err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, fmt.Sprintf("/certificates/%d", c.ID), http.StatusSeeOther)
		return
	}
	s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "cert.delete", c.CommonName,
		"serial="+c.SerialHex, s.clientIP(r))
	s.flash(w, r, "success", "Certificate record deleted.")
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

//
// ---------- CSR tool ----------
//

type csrFormValues struct {
	CommonName, Organization, OrganizationalUnit string
	Country, Province, Locality                  string
	SANs, KeyType                                string
}

func (s *Server) handleCSRToolForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "csr_tool.html", viewData{
		Title: "CSR generator",
		Nav:   "csr",
		Data: map[string]any{
			"Form": csrFormValues{KeyType: firstNonEmpty(s.cfg.CA.DefaultKeyType, string(pki.KeyRSA2048))},
		},
	})
}

func (s *Server) handleCSRToolSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	form := csrFormValues{
		CommonName:         strings.TrimSpace(r.FormValue("common_name")),
		Organization:       strings.TrimSpace(r.FormValue("organization")),
		OrganizationalUnit: strings.TrimSpace(r.FormValue("organizational_unit")),
		Country:            strings.TrimSpace(r.FormValue("country")),
		Province:           strings.TrimSpace(r.FormValue("province")),
		Locality:           strings.TrimSpace(r.FormValue("locality")),
		SANs:               r.FormValue("sans"),
		KeyType:            r.FormValue("key_type"),
	}
	res, err := s.svc.GenerateCSR(r.Context(), ca.GenerateCSRInput{
		Subject: pki.Subject{
			CommonName:         form.CommonName,
			Organization:       form.Organization,
			OrganizationalUnit: form.OrganizationalUnit,
			Country:            form.Country,
			Province:           form.Province,
			Locality:           form.Locality,
		},
		SANs:    splitCSV(form.SANs),
		KeyType: form.KeyType,
	})
	if err != nil {
		s.render(w, r, "csr_tool.html", viewData{
			Title: "CSR generator",
			Nav:   "csr",
			Data:  map[string]any{"Form": form, "Error": err.Error()},
		})
		return
	}

	if r.FormValue("download") == "1" {
		name := safeFileName(form.CommonName)
		writeZip(w, name+"-csr.zip", []zipEntry{
			{Name: name + ".key", Data: []byte(res.PrivateKeyPEM)},
			{Name: name + ".csr", Data: []byte(res.CSRPEM)},
		})
		return
	}

	s.render(w, r, "csr_tool.html", viewData{
		Title: "CSR generator",
		Nav:   "csr",
		Data:  map[string]any{"Form": form, "Result": res},
	})
}

//
// ---------- settings ----------
//

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := currentUser(r)

	scope := u.ID
	if u.IsAdmin() {
		scope = 0 // admins see every token
	}
	tokens, _ := s.auth.ListAPITokens(ctx, scope)

	data := map[string]any{
		"Tokens":          tokens,
		"NewToken":        r.URL.Query().Get("token"),
		"ConfigPath":      s.cfg.Path,
		"DBPath":          s.cfg.DatabaseSummary(),
		"DataDir":         s.cfg.DataDir,
		"SessionTTL":      s.cfg.Security.SessionTTL.String(),
		"DefaultCertDays": s.cfg.CA.DefaultCertDays,
		"DefaultCADays":   s.cfg.CA.DefaultCADays,
		"CRLDays":         s.cfg.CA.CRLDays,
		"LDAP":            s.cfg.Auth.LDAP,
		"OIDC":            s.cfg.Auth.OIDC,
	}
	if u.IsAdmin() {
		users, _ := s.svc.Store().ListUsers(ctx)
		data["Users"] = users
	}
	s.render(w, r, "settings.html", viewData{Title: "Settings", Nav: "settings", Data: data})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")

	full, err := s.svc.Store().GetUserByName(r.Context(), u.Username)
	if err != nil || !auth.CheckPassword(full.PassHash, current) {
		s.flash(w, r, "error", "Your current password is incorrect.")
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.auth.SetPassword(r.Context(), full, next); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.svc.AuditWithIP(r.Context(), u.Username, "user.password_change", u.Username, "", s.clientIP(r))
		s.flash(w, r, "success", "Password updated.")
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	name := strings.TrimSpace(r.FormValue("name"))
	role := r.FormValue("role")
	days := atoiDefault(r.FormValue("days"), 365)
	var ttl time.Duration
	if days > 0 {
		ttl = time.Duration(days) * 24 * time.Hour
	}
	plaintext, rec, err := s.auth.IssueAPIToken(r.Context(), u, name, role, ttl)
	if err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	s.svc.AuditWithIP(r.Context(), u.Username, "token.create", rec.Name, "role="+rec.Role, s.clientIP(r))
	http.Redirect(w, r, "/settings?token="+url.QueryEscape(plaintext), http.StatusSeeOther)
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad token id", err.Error())
		return
	}
	u := currentUser(r)
	// Non-admins may only revoke their own tokens.
	if !u.IsAdmin() {
		mine, _ := s.auth.ListAPITokens(r.Context(), u.ID)
		owned := false
		for _, t := range mine {
			if t.ID == id {
				owned = true
				break
			}
		}
		if !owned {
			s.renderError(w, r, http.StatusForbidden, "Not your token",
				"You can only revoke tokens you created.")
			return
		}
	}
	if err := s.auth.RevokeAPIToken(r.Context(), id); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.svc.AuditWithIP(r.Context(), u.Username, "token.revoke", fmt.Sprint(id), "", s.clientIP(r))
		s.flash(w, r, "success", "Token revoked.")
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	u, err := s.auth.CreateLocalUser(r.Context(),
		strings.TrimSpace(r.FormValue("username")),
		r.FormValue("password"),
		strings.TrimSpace(r.FormValue("display_name")),
		strings.TrimSpace(r.FormValue("email")),
		r.FormValue("role"))
	if err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "user.create", u.Username,
			"role="+u.Role, s.clientIP(r))
		s.flash(w, r, "success", fmt.Sprintf("Local user %q created.", u.Username))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleUserRole(w http.ResponseWriter, r *http.Request) {
	id, target, ok := s.lookupUser(w, r)
	if !ok {
		return
	}
	role := r.FormValue("role")
	if role != store.RoleAdmin {
		role = store.RoleUser
	}
	if role == store.RoleUser && s.isLastAdmin(r, target) {
		s.flash(w, r, "error", "That is the last administrator; promote someone else first.")
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.svc.Store().SetUserRole(r.Context(), id, role); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "user.role", target.Username, role, s.clientIP(r))
		s.flash(w, r, "success", fmt.Sprintf("%s is now %s.", target.Username, role))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleUserDisable(w http.ResponseWriter, r *http.Request) {
	id, target, ok := s.lookupUser(w, r)
	if !ok {
		return
	}
	disabled := r.FormValue("disabled") == "1"
	if disabled && s.isLastAdmin(r, target) {
		s.flash(w, r, "error", "That is the last administrator; it cannot be disabled.")
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.svc.Store().SetUserDisabled(r.Context(), id, disabled); err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if disabled {
		_ = s.svc.Store().DeleteUserSessions(r.Context(), id)
	}
	s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "user.disable", target.Username,
		fmt.Sprintf("disabled=%t", disabled), s.clientIP(r))
	s.flash(w, r, "success", fmt.Sprintf("%s %s.", target.Username, map[bool]string{true: "disabled", false: "enabled"}[disabled]))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id, target, ok := s.lookupUser(w, r)
	if !ok {
		return
	}
	if s.isLastAdmin(r, target) {
		s.flash(w, r, "error", "That is the last administrator; it cannot be deleted.")
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.svc.Store().DeleteUser(r.Context(), id); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "user.delete", target.Username, "", s.clientIP(r))
		s.flash(w, r, "success", fmt.Sprintf("User %q deleted.", target.Username))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleLDAPTest(w http.ResponseWriter, r *http.Request) {
	if !s.auth.LDAPEnabled() {
		s.flash(w, r, "error", "LDAP is not enabled.")
	} else if err := s.auth.LDAP().TestConnection(r.Context()); err != nil {
		s.flash(w, r, "error", "LDAP test failed: "+err.Error())
	} else {
		s.flash(w, r, "success", "LDAP connection, bind and search base all check out.")
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleAuditPage(w http.ResponseWriter, r *http.Request) {
	entries, err := s.svc.Store().ListAudit(r.Context(), 300)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	s.render(w, r, "audit.html", viewData{
		Title: "Audit log", Nav: "audit", Data: map[string]any{"Entries": entries},
	})
}

//
// ---------- shared lookups ----------
//

func (s *Server) lookupCA(w http.ResponseWriter, r *http.Request) (*store.CA, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad authority id", "That is not a valid id.")
		return nil, false
	}
	c, err := s.svc.GetCA(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, "Authority not found",
				"No certificate authority with that id exists.")
		} else {
			s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		}
		return nil, false
	}
	return c, true
}

func (s *Server) lookupCert(w http.ResponseWriter, r *http.Request) (*store.Certificate, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad certificate id", "That is not a valid id.")
		return nil, false
	}
	c, err := s.svc.GetCertificate(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, "Certificate not found",
				"No certificate with that id exists.")
		} else {
			s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		}
		return nil, false
	}
	u := currentUser(r)
	if !u.IsAdmin() && c.RequestedBy != "" && c.RequestedBy != u.Username {
		s.renderError(w, r, http.StatusForbidden, "Not your certificate",
			"You can only view certificates you requested. Ask an administrator if you need this one.")
		return nil, false
	}
	return c, true
}

func (s *Server) lookupUser(w http.ResponseWriter, r *http.Request) (int64, *store.User, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad user id", "That is not a valid id.")
		return 0, nil, false
	}
	u, err := s.svc.Store().GetUser(r.Context(), id)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "User not found", "No user with that id exists.")
		return 0, nil, false
	}
	return id, u, true
}

// isLastAdmin guards against locking everyone out of the portal.
func (s *Server) isLastAdmin(r *http.Request, target *store.User) bool {
	if !target.IsAdmin() {
		return false
	}
	users, err := s.svc.Store().ListUsers(r.Context())
	if err != nil {
		return true // fail closed
	}
	n := 0
	for _, u := range users {
		if u.IsAdmin() && !u.Disabled {
			n++
		}
	}
	return n <= 1
}

//
// ---------- small helpers ----------
//

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	})
	var out []string
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
