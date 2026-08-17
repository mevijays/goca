package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/mevijays/goca/internal/acme"
)

// This file implements the RFC 8555 (ACME) wire protocol itself: parsing the
// JOSE envelope, the RFC-mandated response headers (Replay-Nonce, Location,
// Link), and translating internal/acme's *acme.Problem values into
// application/problem+json responses. None of it decides *what* an ACME
// request is allowed to do - that is entirely internal/acme/service.go. See
// docs/acme-eab.md for the operator-facing story.

const (
	contentTypeJOSE     = "application/jose+json"
	contentTypeJSON     = "application/json"
	contentTypeProblem  = "application/problem+json"
	contentTypePEMChain = "application/pem-certificate-chain"

	// maxACMEBody comfortably covers a JWS carrying a CSR or a certificate
	// for revocation while refusing anything pathological.
	maxACMEBody = 64 * 1024
)

func readACMEBody(r *http.Request) ([]byte, *acme.Problem) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxACMEBody+1))
	if err != nil {
		return nil, acme.Malformed("could not read the request body: %v", err)
	}
	if len(body) > maxACMEBody {
		return nil, acme.Malformed("request body exceeds the %d byte limit", maxACMEBody)
	}
	return body, nil
}

// acmeNonce stamps a fresh Replay-Nonce on the response, as RFC 8555 §6.5
// requires on every response to a POST (this server does it on error
// responses too, which the spec only recommends but costs nothing extra).
func (s *Server) acmeNonce(w http.ResponseWriter) {
	w.Header().Set("Replay-Nonce", s.acme.NewNonce())
}

// acmeError writes an ACME problem document.
func (s *Server) acmeError(w http.ResponseWriter, p *acme.Problem) {
	status := p.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", contentTypeProblem)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

// acmeReply writes a successful JSON resource response, optionally with a
// Location header (new-account, new-order) and Link headers (e.g. an
// authorization or challenge's "up" link back to its order/authorization).
func (s *Server) acmeReply(w http.ResponseWriter, status int, v any, location string, links map[string]string) {
	w.Header().Set("Content-Type", contentTypeJSON)
	if location != "" {
		w.Header().Set("Location", location)
	}
	for rel, url := range links {
		w.Header().Add("Link", fmt.Sprintf(`<%s>;rel="%s"`, url, rel))
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// pathIDACME parses the {id} path segment used throughout the ACME routes.
func pathIDACME(r *http.Request) (int64, *acme.Problem) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, acme.NotFound(fmt.Sprintf("%q is not a valid resource id", r.PathValue("id")))
	}
	return id, nil
}

//
// ---------- directory & nonce ----------
//

func (s *Server) handleACMEDirectory(w http.ResponseWriter, r *http.Request) {
	// A nonce here is a convenience some clients rely on instead of a
	// separate new-nonce round trip; RFC 8555 permits but does not require it.
	s.acmeNonce(w)
	s.acmeReply(w, http.StatusOK, s.acme.Directory(), "", nil)
}

func (s *Server) handleACMENewNonce(w http.ResponseWriter, r *http.Request) {
	s.acmeNonce(w)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

//
// ---------- accounts ----------
//

func (s *Server) handleACMENewAccount(w http.ResponseWriter, r *http.Request) {
	body, perr := readACMEBody(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	account, obj, created, perr := s.acme.NewAccount(r.Context(), body)
	s.acmeNonce(w)
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	s.acmeReply(w, status, obj, s.acme.AccountURL(account.ID), nil)
}

func (s *Server) handleACMEAccount(w http.ResponseWriter, r *http.Request) {
	id, perr := pathIDACME(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	body, perr := readACMEBody(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	obj, perr := s.acme.GetAccount(r.Context(), id, body)
	s.acmeNonce(w)
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	s.acmeReply(w, http.StatusOK, obj, "", nil)
}

//
// ---------- orders ----------
//

func (s *Server) handleACMENewOrder(w http.ResponseWriter, r *http.Request) {
	body, perr := readACMEBody(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	order, obj, perr := s.acme.NewOrder(r.Context(), body)
	s.acmeNonce(w)
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	s.acmeReply(w, http.StatusCreated, obj, s.acme.OrderURL(order.ID), nil)
}

func (s *Server) handleACMEOrder(w http.ResponseWriter, r *http.Request) {
	id, perr := pathIDACME(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	body, perr := readACMEBody(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	obj, perr := s.acme.GetOrder(r.Context(), id, body)
	s.acmeNonce(w)
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	s.acmeReply(w, http.StatusOK, obj, "", nil)
}

func (s *Server) handleACMEFinalize(w http.ResponseWriter, r *http.Request) {
	id, perr := pathIDACME(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	body, perr := readACMEBody(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	obj, perr := s.acme.Finalize(r.Context(), id, body)
	s.acmeNonce(w)
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	s.acmeReply(w, http.StatusOK, obj, s.acme.OrderURL(id), nil)
}

//
// ---------- authorizations & challenges ----------
//

func (s *Server) handleACMEAuthz(w http.ResponseWriter, r *http.Request) {
	id, perr := pathIDACME(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	body, perr := readACMEBody(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	obj, perr := s.acme.GetAuthorization(r.Context(), id, body)
	s.acmeNonce(w)
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	s.acmeReply(w, http.StatusOK, obj, "", nil)
}

func (s *Server) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	id, perr := pathIDACME(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	body, perr := readACMEBody(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	obj, perr := s.acme.GetChallenge(r.Context(), id, body)
	s.acmeNonce(w)
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	s.acmeReply(w, http.StatusOK, obj, "", nil)
}

//
// ---------- certificates ----------
//

func (s *Server) handleACMECert(w http.ResponseWriter, r *http.Request) {
	id, perr := pathIDACME(r)
	if perr != nil {
		if r.Method == http.MethodPost {
			s.acmeNonce(w)
		}
		s.acmeError(w, perr)
		return
	}
	// The download itself needs no further authentication once the id is
	// known: it is an unguessable, per-issuance identifier, and the
	// certificate is a public artefact goca already serves unauthenticated
	// elsewhere (/public/ca, cert.pem downloads). A POST-as-GET body, if
	// present, is accepted but not required to validate.
	if r.Method == http.MethodPost {
		if _, perr := readACMEBody(r); perr != nil {
			s.acmeNonce(w)
			s.acmeError(w, perr)
			return
		}
	}
	chain, perr := s.acme.GetCertificatePEM(r.Context(), id)
	if r.Method == http.MethodPost {
		s.acmeNonce(w)
	}
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	w.Header().Set("Content-Type", contentTypePEMChain)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(chain)
}

func (s *Server) handleACMERevokeCert(w http.ResponseWriter, r *http.Request) {
	body, perr := readACMEBody(r)
	if perr != nil {
		s.acmeNonce(w)
		s.acmeError(w, perr)
		return
	}
	perr = s.acme.RevokeCert(r.Context(), body)
	s.acmeNonce(w)
	if perr != nil {
		s.acmeError(w, perr)
		return
	}
	s.acmeReply(w, http.StatusOK, map[string]any{}, "", nil)
}
