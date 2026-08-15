package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/mevijays/goca/internal/acme"
)

// This file is the operator-facing side of ACME: creating and retiring EAB
// credentials, and viewing accounts they bootstrapped. It has nothing to do
// with the wire protocol (acme_protocol.go) - these are ordinary portal pages
// and REST API endpoints, authenticated the normal goca way (session or
// bearer token), same as everything else in the CLI/API/portal trio.

//
// ---------- portal page ----------
//

func (s *Server) handleACMESettings(w http.ResponseWriter, r *http.Request) {
	creds, err := s.acme.ListEAB(r.Context())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	accounts, err := s.acme.ListAccounts(r.Context())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	cas, err := s.svc.ListCAs(r.Context())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	s.render(w, r, "acme.html", viewData{
		Title: "ACME",
		Nav:   "acme",
		Data: map[string]any{
			"Creds":        creds,
			"Accounts":     accounts,
			"CAs":          cas,
			"DirectoryURL": s.acme.DirectoryURL(),
			"NewSecret":    r.URL.Query().Get("secret"),
			"NewKeyID":     r.URL.Query().Get("key_id"),
		},
	})
}

func (s *Server) handleACMEEABCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	days, _ := strconv.Atoi(r.FormValue("days"))
	maxAccounts, _ := strconv.Atoi(r.FormValue("max_accounts"))
	expiresIn, _ := strconv.Atoi(r.FormValue("expires_in_days"))

	res, err := s.acme.CreateEAB(r.Context(), acme.CreateEABInput{
		Name:           strings.TrimSpace(r.FormValue("name")),
		CARef:          r.FormValue("ca"),
		Profile:        r.FormValue("profile"),
		Days:           days,
		AllowedDomains: splitCSV(r.FormValue("allowed_domains")),
		MaxAccounts:    maxAccounts,
		ExpiresInDays:  expiresIn,
		Actor:          currentUser(r).Username,
	})
	if err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, "/settings/acme", http.StatusSeeOther)
		return
	}
	q := "?key_id=" + res.Cred.KeyID + "&secret=" + res.HMACKeyB64
	http.Redirect(w, r, "/settings/acme"+q, http.StatusSeeOther)
}

func (s *Server) handleACMEEABDisable(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad credential id", err.Error())
		return
	}
	disabled := r.FormValue("disabled") != "0"
	if err := s.acme.SetEABDisabled(r.Context(), id, disabled, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else if disabled {
		s.flash(w, r, "success", "Credential disabled. Accounts it already created keep working.")
	} else {
		s.flash(w, r, "success", "Credential re-enabled.")
	}
	http.Redirect(w, r, "/settings/acme", http.StatusSeeOther)
}

func (s *Server) handleACMEEABDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad credential id", err.Error())
		return
	}
	if err := s.acme.DeleteEAB(r.Context(), id, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", "Credential deleted.")
	}
	http.Redirect(w, r, "/settings/acme", http.StatusSeeOther)
}

//
// ---------- REST API ----------
//

func (s *Server) apiACMEEABList(w http.ResponseWriter, r *http.Request) error {
	creds, err := s.acme.ListEAB(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": creds})
	return nil
}

func (s *Server) apiACMEEABCreate(w http.ResponseWriter, r *http.Request) error {
	var in acme.CreateEABInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	in.Actor = currentUser(r).Username
	res, err := s.acme.CreateEAB(r.Context(), in)
	if err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"credential": res.Cred,
		"hmac_key":   res.HMACKeyB64,
	})
	return nil
}

func (s *Server) apiACMEEABGet(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	c, err := s.acme.GetEAB(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, c)
	return nil
}

func (s *Server) apiACMEEABDisable(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var body struct {
		Disabled *bool `json:"disabled"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &body); err != nil {
			return err
		}
	}
	disabled := true
	if body.Disabled != nil {
		disabled = *body.Disabled
	}
	if err := s.acme.SetEABDisabled(r.Context(), id, disabled, currentUser(r).Username); err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": disabled})
	return nil
}

func (s *Server) apiACMEEABDelete(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	if err := s.acme.DeleteEAB(r.Context(), id, currentUser(r).Username); err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}

func (s *Server) apiACMEAccountList(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.acme.ListAccounts(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts})
	return nil
}

func (s *Server) apiACMEAccountGet(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	a, err := s.acme.GetAccountByID(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, a)
	return nil
}

func (s *Server) apiACMEAccountOrders(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	orders, err := s.acme.ListOrders(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": orders})
	return nil
}
