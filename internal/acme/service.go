package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/metrics"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// orderTTL and authzTTL bound how long an order/authorization is considered
// current. goca does not garbage-collect expired rows (they're small and the
// history has audit value), this only affects the "expires" field clients see.
const (
	orderTTL = 24 * time.Hour
	authzTTL = 24 * time.Hour
)

// Service implements the RFC 8555 state machine on top of goca's existing
// certificate service. It owns nothing of its own except in-memory nonces -
// every certificate, key and audit entry it produces goes through ca.Service
// exactly like the CLI, the API and the portal do.
type Service struct {
	caSvc  *ca.Service
	st     *store.Store
	nonces *NonceManager
}

// New builds an ACME service bound to an existing certificate service.
func New(caSvc *ca.Service) *Service {
	return &Service{caSvc: caSvc, st: caSvc.Store(), nonces: NewNonceManager()}
}

func (s *Service) audit(ctx context.Context, actor, action, target, detail string) {
	s.caSvc.AuditWithIP(ctx, actor, action, target, detail, "")
}

//
// ---------- URLs ----------
//

func (s *Service) acmeBase() string {
	return strings.TrimRight(s.caSvc.Config().Server.BaseURL, "/") + "/acme"
}

func (s *Service) directoryURL() string  { return s.acmeBase() + "/directory" }
func (s *Service) newNonceURL() string   { return s.acmeBase() + "/new-nonce" }
func (s *Service) newAccountURL() string { return s.acmeBase() + "/new-account" }
func (s *Service) newOrderURL() string   { return s.acmeBase() + "/new-order" }
func (s *Service) revokeCertURL() string { return s.acmeBase() + "/revoke-cert" }

func (s *Service) accountURL(id int64) string { return fmt.Sprintf("%s/account/%d", s.acmeBase(), id) }
func (s *Service) accountOrdersURL(id int64) string {
	return fmt.Sprintf("%s/account/%d/orders", s.acmeBase(), id)
}
func (s *Service) orderURL(id int64) string { return fmt.Sprintf("%s/order/%d", s.acmeBase(), id) }
func (s *Service) finalizeURL(id int64) string {
	return fmt.Sprintf("%s/order/%d/finalize", s.acmeBase(), id)
}
func (s *Service) authzURL(id int64) string { return fmt.Sprintf("%s/authz/%d", s.acmeBase(), id) }
func (s *Service) challengeURL(id int64) string {
	return fmt.Sprintf("%s/challenge/%d", s.acmeBase(), id)
}
func (s *Service) certURL(id int64) string { return fmt.Sprintf("%s/cert/%d", s.acmeBase(), id) }

// Exported URL builders, for the HTTP layer to fill in Location and Link
// response headers (RFC 8555 requires these outside the JSON body itself).
func (s *Service) DirectoryURL() string       { return s.directoryURL() }
func (s *Service) AccountURL(id int64) string { return s.accountURL(id) }
func (s *Service) OrderURL(id int64) string   { return s.orderURL(id) }
func (s *Service) AuthzURL(id int64) string   { return s.authzURL(id) }

var accountURLRe = regexp.MustCompile(`/acme/account/(\d+)$`)

//
// ---------- directory & nonce ----------
//

// Directory returns the RFC 8555 §7.1.1 directory object.
func (s *Service) Directory() Directory {
	return Directory{
		NewNonce:   s.newNonceURL(),
		NewAccount: s.newAccountURL(),
		NewOrder:   s.newOrderURL(),
		RevokeCert: s.revokeCertURL(),
		Meta: &DirectoryMeta{
			ExternalAccountRequired: true,
			Website:                 s.caSvc.Config().Server.BaseURL,
		},
	}
}

// NewNonce issues a fresh replay nonce.
func (s *Service) NewNonce() string { return s.nonces.New() }

// checkURL enforces RFC 8555 §6.4: a JWS's "url" header must equal the URL
// the server itself expects for this operation, not merely be well-formed.
func (s *Service) checkURL(jws *ParsedJWS, want string) *Problem {
	if jws.URL != want {
		return Unauthorized("this request's url header does not match the endpoint it was sent to")
	}
	return nil
}

func (s *Service) checkNonce(jws *ParsedJWS) *Problem {
	if !s.nonces.Consume(jws.Nonce) {
		return BadNonce("the nonce was missing, unknown, or already used")
	}
	return nil
}

//
// ---------- accounts ----------
//

func (s *Service) accountObject(a *store.AcmeAccount) *AccountObject {
	return &AccountObject{Status: a.Status, Contact: a.Contact, Orders: s.accountOrdersURL(a.ID)}
}

// NewAccount handles POST /new-account (§7.3). An account is created only
// when the request carries a valid externalAccountBinding for a usable EAB
// credential; there is no other way to register with this server. The bool
// return is true only when a new account was created - §7.3.1 requires a 200
// rather than 201 when an existing registration is returned instead.
func (s *Service) NewAccount(ctx context.Context, body []byte) (*store.AcmeAccount, *AccountObject, bool, *Problem) {
	jws, err := ParseJWS(body)
	if err != nil {
		return nil, nil, false, Malformed("%v", err)
	}
	if pr := s.checkURL(jws, s.newAccountURL()); pr != nil {
		return nil, nil, false, pr
	}
	if pr := s.checkNonce(jws); pr != nil {
		return nil, nil, false, pr
	}
	if jws.JWK == nil {
		return nil, nil, false, Malformed("new-account requests must be signed with an embedded jwk, not kid")
	}
	if err := jws.Verify(jws.JWK); err != nil {
		return nil, nil, false, Malformed("%v", err)
	}
	var req NewAccountRequest
	if err := jws.DecodePayload(&req); err != nil {
		return nil, nil, false, Malformed("%v", err)
	}

	thumb, err := Thumbprint(jws.JWK)
	if err != nil {
		return nil, nil, false, ServerInternal("compute account key thumbprint: %v", err)
	}

	// Idempotent per §7.3.1: a repeat registration with the same key returns
	// the existing account instead of erroring or creating a duplicate.
	if existing, err := s.st.GetAcmeAccountByThumbprint(ctx, thumb); err == nil {
		_ = s.st.TouchAcmeAccountUsed(ctx, existing.ID)
		return existing, s.accountObject(existing), false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, false, ServerInternal("%v", err)
	}
	if req.OnlyReturnExisting {
		return nil, nil, false, AccountDoesNotExist("no account is registered for this key")
	}

	var cred *store.EABCred
	keyID, err := VerifyEAB(req.ExternalAccountBinding, jws.URL, jws.JWK, func(kid string) ([]byte, bool) {
		c, lookupErr := s.st.GetEABCredByKeyID(ctx, kid)
		if lookupErr != nil {
			return nil, false
		}
		key, decErr := s.caSvc.Box().Decrypt(c.HMACKeyEnc)
		if decErr != nil {
			return nil, false
		}
		cred = c
		return key, true
	})
	if err != nil {
		s.audit(ctx, "acme", "acme.account.rejected", keyID, err.Error())
		return nil, nil, false, ExternalAccountRequired(err.Error())
	}
	if !cred.Usable() {
		reason := "the external account binding key is disabled, expired, or has reached its account limit"
		s.audit(ctx, "acme", "acme.account.rejected", keyID, reason)
		return nil, nil, false, ExternalAccountRequired(reason)
	}

	jwkJSON, err := json.Marshal(jws.JWK.Public())
	if err != nil {
		return nil, nil, false, ServerInternal("%v", err)
	}
	account, err := s.st.CreateAcmeAccount(ctx, &store.AcmeAccount{
		EABID:         cred.ID,
		JWKJSON:       string(jwkJSON),
		JWKThumbprint: thumb,
		Contact:       req.Contact,
		Status:        store.AcmeStatusValid,
		CreatedAt:     time.Now().UTC(),
	})
	if err != nil {
		return nil, nil, false, ServerInternal("%v", err)
	}
	_ = s.st.TouchEABCredUse(ctx, cred.ID)
	s.audit(ctx, "acme:"+cred.Name, "acme.account.create", fmt.Sprint(account.ID),
		fmt.Sprintf("eab=%s contact=%v", cred.Name, req.Contact))
	metrics.AccountTotal.WithLabelValues(account.Status).Inc()
	return account, s.accountObject(account), true, nil
}

// authedRequest is a request that has been fully authenticated against an
// existing account's key.
type authedRequest struct {
	jws     *ParsedJWS
	account *store.AcmeAccount
}

// ResolveAccount loads the account a "kid" header refers to and checks it is
// still usable.
func (s *Service) ResolveAccount(ctx context.Context, kid string) (*store.AcmeAccount, *Problem) {
	m := accountURLRe.FindStringSubmatch(kid)
	if m == nil {
		return nil, AccountDoesNotExist("malformed account url")
	}
	var id int64
	fmt.Sscanf(m[1], "%d", &id)
	a, err := s.st.GetAcmeAccount(ctx, id)
	if err != nil {
		return nil, AccountDoesNotExist("no such account")
	}
	if a.Status != store.AcmeStatusValid {
		return nil, Unauthorized("this account is %s", a.Status)
	}
	return a, nil
}

// authenticate is the common path for every endpoint that must be signed by
// an existing account: parse, check url/nonce, resolve the account from kid,
// verify against its stored key.
func (s *Service) authenticate(ctx context.Context, body []byte, expectedURL string) (*authedRequest, *Problem) {
	jws, err := ParseJWS(body)
	if err != nil {
		return nil, Malformed("%v", err)
	}
	if pr := s.checkURL(jws, expectedURL); pr != nil {
		return nil, pr
	}
	if pr := s.checkNonce(jws); pr != nil {
		return nil, pr
	}
	if jws.KeyID == "" {
		return nil, Malformed("this request must be signed with kid, not an embedded jwk")
	}
	account, perr := s.ResolveAccount(ctx, jws.KeyID)
	if perr != nil {
		return nil, perr
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(account.JWKJSON), &jwk); err != nil {
		return nil, ServerInternal("stored account key is corrupt: %v", err)
	}
	if err := jws.Verify(&jwk); err != nil {
		return nil, Malformed("%v", err)
	}
	_ = s.st.TouchAcmeAccountUsed(ctx, account.ID)
	return &authedRequest{jws: jws, account: account}, nil
}

// GetAccount handles a POST-as-GET (or contact/deactivate update) to an
// account URL (§7.3.2, §7.3.6).
func (s *Service) GetAccount(ctx context.Context, accountID int64, body []byte) (*AccountObject, *Problem) {
	ar, perr := s.authenticate(ctx, body, s.accountURL(accountID))
	if perr != nil {
		return nil, perr
	}
	if ar.account.ID != accountID {
		return nil, Unauthorized("this is not your account")
	}
	if ar.jws.IsPostAsGet() {
		return s.accountObject(ar.account), nil
	}

	var req UpdateAccountRequest
	if err := ar.jws.DecodePayload(&req); err != nil {
		return nil, Malformed("%v", err)
	}
	if req.Contact != nil {
		if err := s.st.SetAcmeAccountContact(ctx, ar.account.ID, req.Contact); err != nil {
			return nil, ServerInternal("%v", err)
		}
		ar.account.Contact = req.Contact
	}
	if req.Status == store.AcmeStatusDeactivated {
		if err := s.st.SetAcmeAccountStatus(ctx, ar.account.ID, store.AcmeStatusDeactivated); err != nil {
			return nil, ServerInternal("%v", err)
		}
		ar.account.Status = store.AcmeStatusDeactivated
		s.audit(ctx, fmt.Sprintf("acme:account:%d", ar.account.ID), "acme.account.deactivate",
			fmt.Sprint(ar.account.ID), "")
	} else if req.Status != "" {
		return nil, Malformed("status can only be set to %q", store.AcmeStatusDeactivated)
	}
	return s.accountObject(ar.account), nil
}

//
// ---------- orders ----------
//

// NewOrder handles POST /new-order (§7.4). Every identifier is checked
// against the account's EAB credential's allowed-domain scope, then every
// authorization (and its structurally-complete but already-satisfied
// challenge) is created valid: EAB was the whole trust decision, made once,
// at account registration.
func (s *Service) NewOrder(ctx context.Context, body []byte) (*store.AcmeOrder, *OrderObject, *Problem) {
	ar, perr := s.authenticate(ctx, body, s.newOrderURL())
	if perr != nil {
		return nil, nil, perr
	}
	var req NewOrderRequest
	if err := ar.jws.DecodePayload(&req); err != nil {
		return nil, nil, Malformed("%v", err)
	}
	if len(req.Identifiers) == 0 {
		return nil, nil, Malformed("an order must request at least one identifier")
	}

	cred, err := s.st.GetEABCred(ctx, ar.account.EABID)
	if err != nil {
		return nil, nil, ServerInternal("%v", err)
	}

	idents := make([]store.AcmeIdentifier, 0, len(req.Identifiers))
	for _, id := range req.Identifiers {
		typ := strings.ToLower(strings.TrimSpace(id.Type))
		if typ == "" {
			typ = "dns"
		}
		if typ != "dns" {
			return nil, nil, UnsupportedIdentifier("identifier type %q is not supported; only \"dns\" is", typ)
		}
		val := strings.ToLower(strings.TrimSpace(id.Value))
		if val == "" {
			return nil, nil, Malformed("an identifier value must not be empty")
		}
		if !domainAllowed(cred.AllowedDomains, val) {
			return nil, nil, RejectedIdentifier(
				"%q is outside the domains permitted for this account's credential %q", val, cred.Name)
		}
		idents = append(idents, store.AcmeIdentifier{Type: "dns", Value: val})
	}

	now := time.Now().UTC()
	// Every identifier is authorized immediately, so the order needs no
	// intermediate "pending" period - it starts "ready" per the §7.1.6 state
	// diagram's allowance for orders whose authorizations are already valid.
	order, err := s.st.CreateAcmeOrder(ctx, &store.AcmeOrder{
		AccountID:   ar.account.ID,
		Status:      store.AcmeStatusReady,
		Identifiers: idents,
		ExpiresAt:   now.Add(orderTTL),
		CreatedAt:   now,
	})
	if err != nil {
		return nil, nil, ServerInternal("%v", err)
	}

	for _, id := range idents {
		authz, err := s.st.CreateAcmeAuthorization(ctx, &store.AcmeAuthorization{
			OrderID:         order.ID,
			IdentifierType:  id.Type,
			IdentifierValue: id.Value,
			Wildcard:        strings.HasPrefix(id.Value, "*."),
			Status:          store.AcmeStatusValid,
			ExpiresAt:       now.Add(authzTTL),
			CreatedAt:       now,
		})
		if err != nil {
			return nil, nil, ServerInternal("%v", err)
		}
		token, err := randomToken()
		if err != nil {
			return nil, nil, ServerInternal("%v", err)
		}
		validated := now
		if _, err := s.st.CreateAcmeChallenge(ctx, &store.AcmeChallenge{
			AuthorizationID: authz.ID,
			Type:            "http-01",
			Token:           token,
			Status:          store.AcmeStatusValid,
			ValidatedAt:     &validated,
			CreatedAt:       now,
		}); err != nil {
			return nil, nil, ServerInternal("%v", err)
		}
		metrics.ChallengeTotal.WithLabelValues(store.AcmeStatusValid).Inc()
	}

	obj, err := s.OrderObjectFor(ctx, order)
	if err != nil {
		return nil, nil, ServerInternal("%v", err)
	}
	s.audit(ctx, fmt.Sprintf("acme:account:%d", ar.account.ID), "acme.order.create", fmt.Sprint(order.ID),
		fmt.Sprintf("identifiers=%v eab=%s", req.Identifiers, cred.Name))
	metrics.OrderTotal.WithLabelValues(order.Status).Inc()
	return order, obj, nil
}

// OrderObjectFor builds the wire representation of a stored order.
func (s *Service) OrderObjectFor(ctx context.Context, o *store.AcmeOrder) (*OrderObject, error) {
	authzs, err := s.st.ListAcmeAuthorizationsByOrder(ctx, o.ID)
	if err != nil {
		return nil, err
	}
	urls := make([]string, 0, len(authzs))
	for _, a := range authzs {
		urls = append(urls, s.authzURL(a.ID))
	}
	idents := make([]Identifier, 0, len(o.Identifiers))
	for _, id := range o.Identifiers {
		idents = append(idents, Identifier{Type: id.Type, Value: id.Value})
	}
	obj := &OrderObject{
		Status:         o.Status,
		Expires:        o.ExpiresAt.UTC().Format(time.RFC3339),
		Identifiers:    idents,
		Authorizations: urls,
		Finalize:       s.finalizeURL(o.ID),
	}
	if o.CertificateID != nil {
		obj.Certificate = s.certURL(*o.CertificateID)
	}
	if o.Error != "" {
		var p Problem
		if json.Unmarshal([]byte(o.Error), &p) == nil {
			obj.Error = &p
		}
	}
	return obj, nil
}

// GetOrder handles a POST-as-GET to an order URL.
func (s *Service) GetOrder(ctx context.Context, orderID int64, body []byte) (*OrderObject, *Problem) {
	ar, perr := s.authenticate(ctx, body, s.orderURL(orderID))
	if perr != nil {
		return nil, perr
	}
	order, err := s.st.GetAcmeOrder(ctx, orderID)
	if err != nil {
		return nil, NotFound("no such order")
	}
	if order.AccountID != ar.account.ID {
		return nil, Unauthorized("this order does not belong to your account")
	}
	obj, err := s.OrderObjectFor(ctx, order)
	if err != nil {
		return nil, ServerInternal("%v", err)
	}
	return obj, nil
}

// Finalize handles POST /order/{id}/finalize (§7.4): submits the CSR, checks
// it requests exactly the order's authorized identifiers, and signs it
// through the normal certificate service - the same Issue() path the CLI, the
// API and the portal use, so an ACME-issued certificate is a completely
// ordinary goca certificate from that point on (renewable, revocable,
// exportable, searchable) with its provenance recorded as "acme:<eab name>"
// in the usual requested-by field.
func (s *Service) Finalize(ctx context.Context, orderID int64, body []byte) (*OrderObject, *Problem) {
	ar, perr := s.authenticate(ctx, body, s.finalizeURL(orderID))
	if perr != nil {
		return nil, perr
	}
	order, err := s.st.GetAcmeOrder(ctx, orderID)
	if err != nil {
		return nil, NotFound("no such order")
	}
	if order.AccountID != ar.account.ID {
		return nil, Unauthorized("this order does not belong to your account")
	}
	if order.Status != store.AcmeStatusReady {
		return nil, OrderNotReady(fmt.Sprintf("order is %q, not ready", order.Status))
	}

	var req FinalizeRequest
	if err := ar.jws.DecodePayload(&req); err != nil {
		return nil, Malformed("%v", err)
	}
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		return nil, BadCSR("csr is not valid base64url: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	csr, err := pki.ParseCSR(csrPEM)
	if err != nil {
		return nil, BadCSR("%v", err)
	}

	want := map[string]bool{}
	for _, id := range order.Identifiers {
		want[id.Value] = true
	}
	got := map[string]bool{}
	for _, n := range csr.DNSNames {
		got[strings.ToLower(n)] = true
	}
	if !sameStringSet(want, got) {
		p := BadCSR("the CSR's names %v do not match the order's authorized identifiers %v",
			sortedKeys(got), sortedKeys(want))
		_ = s.st.SetAcmeOrderError(ctx, order.ID, mustJSON(p))
		return nil, p
	}

	cred, err := s.st.GetEABCred(ctx, ar.account.EABID)
	if err != nil {
		return nil, ServerInternal("%v", err)
	}

	issueIn := ca.IssueInput{
		Mode:    ca.ModeCSR,
		CSRPEM:  string(csrPEM),
		Profile: cred.Profile,
		Days:    cred.Days,
		Actor:   "acme:" + cred.Name,
	}
	if cred.CAID != nil {
		issueIn.CARef = fmt.Sprint(*cred.CAID)
	}
	if csr.Subject.CommonName == "" && len(order.Identifiers) > 0 {
		// Give the certificate a legible common name for the rest of goca's
		// UI/CLI even though the client's CSR left it blank, which most
		// modern ACME clients (cert-manager included) do.
		issueIn.Subject.CommonName = order.Identifiers[0].Value
	}

	res, err := s.caSvc.Issue(ctx, issueIn)
	if err != nil {
		p := ServerInternal("issuance failed: %v", err)
		_ = s.st.SetAcmeOrderError(ctx, order.ID, mustJSON(p))
		return nil, p
	}
	if err := s.st.SetAcmeOrderCertificate(ctx, order.ID, res.Certificate.ID); err != nil {
		return nil, ServerInternal("%v", err)
	}
	s.audit(ctx, "acme:"+cred.Name, "acme.order.finalize", fmt.Sprint(order.ID),
		fmt.Sprintf("serial=%s cn=%s", res.Certificate.SerialHex, res.Certificate.CommonName))
	metrics.OrderTotal.WithLabelValues("finalized").Inc()

	updated, err := s.st.GetAcmeOrder(ctx, order.ID)
	if err != nil {
		return nil, ServerInternal("%v", err)
	}
	obj, err := s.OrderObjectFor(ctx, updated)
	if err != nil {
		return nil, ServerInternal("%v", err)
	}
	return obj, nil
}

//
// ---------- authorizations & challenges ----------
//

func authzObject(s *Service, a *store.AcmeAuthorization, challenges []*store.AcmeChallenge) *AuthorizationObject {
	chs := make([]ChallengeObject, 0, len(challenges))
	for _, c := range challenges {
		co := ChallengeObject{Type: c.Type, URL: s.challengeURL(c.ID), Status: c.Status, Token: c.Token}
		if c.ValidatedAt != nil {
			co.Validated = c.ValidatedAt.UTC().Format(time.RFC3339)
		}
		chs = append(chs, co)
	}
	return &AuthorizationObject{
		Identifier: Identifier{Type: a.IdentifierType, Value: a.IdentifierValue},
		Status:     a.Status,
		Expires:    a.ExpiresAt.UTC().Format(time.RFC3339),
		Challenges: chs,
		Wildcard:   a.Wildcard,
	}
}

// GetAuthorization handles a POST-as-GET to an authorization URL (§7.5).
func (s *Service) GetAuthorization(ctx context.Context, authzID int64, body []byte) (*AuthorizationObject, *Problem) {
	authz, err := s.st.GetAcmeAuthorization(ctx, authzID)
	if err != nil {
		return nil, NotFound("no such authorization")
	}
	order, err := s.st.GetAcmeOrder(ctx, authz.OrderID)
	if err != nil {
		return nil, NotFound("no such authorization")
	}
	ar, perr := s.authenticate(ctx, body, s.authzURL(authzID))
	if perr != nil {
		return nil, perr
	}
	if order.AccountID != ar.account.ID {
		return nil, Unauthorized("this authorization does not belong to your account")
	}
	challenges, err := s.st.ListAcmeChallengesByAuthorization(ctx, authz.ID)
	if err != nil {
		return nil, ServerInternal("%v", err)
	}
	return authzObject(s, authz, challenges), nil
}

// GetChallenge handles a POST to a challenge URL (§7.5.1): fetching it, or
// "triggering" it. Both return the same object, since it is created already
// valid - there is nothing to trigger.
func (s *Service) GetChallenge(ctx context.Context, challengeID int64, body []byte) (*ChallengeObject, *Problem) {
	c, err := s.st.GetAcmeChallenge(ctx, challengeID)
	if err != nil {
		return nil, NotFound("no such challenge")
	}
	authz, err := s.st.GetAcmeAuthorization(ctx, c.AuthorizationID)
	if err != nil {
		return nil, NotFound("no such challenge")
	}
	order, err := s.st.GetAcmeOrder(ctx, authz.OrderID)
	if err != nil {
		return nil, NotFound("no such challenge")
	}
	ar, perr := s.authenticate(ctx, body, s.challengeURL(challengeID))
	if perr != nil {
		return nil, perr
	}
	if order.AccountID != ar.account.ID {
		return nil, Unauthorized("this challenge does not belong to your account")
	}
	co := ChallengeObject{Type: c.Type, URL: s.challengeURL(c.ID), Status: c.Status, Token: c.Token}
	if c.ValidatedAt != nil {
		co.Validated = c.ValidatedAt.UTC().Format(time.RFC3339)
	}
	return &co, nil
}

//
// ---------- certificates ----------
//

// GetCertificatePEM returns the leaf certificate followed by its full issuing
// chain, in PEM - what RFC 8555 §7.4.2 expects the certificate resource to
// serve. certID is a goca certificates.id, taken from an order's Certificate
// field or the /acme/cert/{id} URL.
func (s *Service) GetCertificatePEM(ctx context.Context, certID int64) ([]byte, *Problem) {
	rec, err := s.caSvc.GetCertificate(ctx, certID)
	if err != nil {
		return nil, NotFound("no such certificate")
	}
	chain, err := s.caSvc.CertChainPEM(ctx, rec)
	if err != nil {
		return nil, ServerInternal("%v", err)
	}
	return chain, nil
}

// equalPublicKey is satisfied by every crypto.PublicKey type the standard
// library returns from x509 parsing (Go 1.20+).
type equalPublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// RevokeCert handles POST /revoke-cert (§7.6). The request may be signed by
// an account's key - in which case it must be the account whose EAB
// credential's name matches the certificate's recorded requester - or by the
// certificate's own key pair, proven by embedding a jwk that equals the
// certificate's public key.
func (s *Service) RevokeCert(ctx context.Context, body []byte) *Problem {
	jws, err := ParseJWS(body)
	if err != nil {
		return Malformed("%v", err)
	}
	if pr := s.checkURL(jws, s.revokeCertURL()); pr != nil {
		return pr
	}
	if pr := s.checkNonce(jws); pr != nil {
		return pr
	}

	var account *store.AcmeAccount
	if jws.KeyID != "" {
		a, perr := s.ResolveAccount(ctx, jws.KeyID)
		if perr != nil {
			return perr
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal([]byte(a.JWKJSON), &jwk); err != nil {
			return ServerInternal("%v", err)
		}
		if err := jws.Verify(&jwk); err != nil {
			return Malformed("%v", err)
		}
		account = a
	} else {
		if err := jws.Verify(jws.JWK); err != nil {
			return Malformed("%v", err)
		}
	}

	var req RevokeCertRequest
	if err := jws.DecodePayload(&req); err != nil {
		return Malformed("%v", err)
	}
	der, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		return Malformed("certificate is not valid base64url: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Malformed("certificate does not parse: %v", err)
	}

	if account == nil {
		eq, ok := leaf.PublicKey.(equalPublicKey)
		if !ok || !eq.Equal(jws.JWK.Key) {
			return Unauthorized("the signing key does not match the certificate's own key")
		}
	}

	rec, err := s.st.GetCertificateBySerial(ctx, pki.SerialHex(leaf.SerialNumber))
	if err != nil {
		return NotFound("no matching certificate is known to this server")
	}
	if rec.Fingerprint != pki.FingerprintSHA256(der) {
		return Malformed("the supplied certificate does not match the one this server issued for that serial")
	}
	if rec.Status == store.StatusRevoked {
		return AlreadyRevoked("this certificate is already revoked")
	}

	actor := "acme:cert-key"
	if account != nil {
		cred, err := s.st.GetEABCred(ctx, account.EABID)
		if err != nil {
			return ServerInternal("%v", err)
		}
		if rec.RequestedBy != "acme:"+cred.Name {
			return Unauthorized("this account is not authorized to revoke this certificate")
		}
		actor = "acme:" + cred.Name
	}

	reason := 0
	if req.Reason != nil {
		reason = *req.Reason
	}
	if reason < 0 || reason == 7 || reason > 10 {
		return BadRevocationReason(fmt.Sprintf("%d is not a valid CRL revocation reason", reason))
	}
	if err := s.caSvc.Revoke(ctx, rec.ID, reason, actor); err != nil {
		return ServerInternal("%v", err)
	}
	return nil
}

//
// ---------- small helpers ----------
//

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustJSON(p *Problem) string {
	b, err := json.Marshal(p)
	if err != nil {
		return `{"type":"` + errNS + `serverInternal","detail":"internal error"}`
	}
	return string(b)
}
