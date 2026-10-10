package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// This file is the operator-facing half of ACME support: creating, listing
// and retiring EAB credentials. It has nothing to do with the wire protocol -
// see service.go for that - and is what the CLI, the REST API and the portal
// all call, the same way every other capability in goca goes through one
// shared implementation.

// CreateEABInput describes a new EAB credential.
type CreateEABInput struct {
	Name string `json:"name"`
	// CARef selects the authority accounts bootstrapped with this credential
	// issue from; empty means "the default issuing CA, resolved at request
	// time" so it follows if the default changes later.
	CARef string `json:"ca"`
	// Profile sets key usage/extended key usage on issued certificates.
	Profile string `json:"profile"`
	// Days is the certificate validity; 0 means the CA's/global default.
	Days int `json:"days"`
	// AllowedDomains restricts which identifiers an order from an account
	// bootstrapped with this credential may request.
	AllowedDomains []string `json:"allowed_domains"`
	// AllowAnyDomain must be set to create a credential with no
	// AllowedDomains. goca grants ACME authorizations without any
	// domain-control check, so such a credential can obtain a certificate for
	// any hostname at all - goca's own, the ingress gateway's, anything the
	// issuing CA is trusted for. That used to be what simply leaving the
	// domains blank did; it now has to be asked for.
	AllowAnyDomain bool `json:"allow_any_domain"`
	// MaxAccounts caps how many ACME accounts may be bootstrapped with this
	// credential; 0 means unlimited.
	MaxAccounts int `json:"max_accounts"`
	// ExpiresInDays, if positive, disables the credential automatically after
	// that many days (it does not affect certificates or accounts already
	// created with it).
	ExpiresInDays int    `json:"expires_in_days"`
	Actor         string `json:"-"`
}

// CreateEABResult carries the credential plus its plaintext HMAC key, which is
// shown to the operator exactly once.
type CreateEABResult struct {
	Cred       *store.EABCred `json:"cred"`
	HMACKeyB64 string         `json:"hmac_key"` // base64url, unpadded - what goes in the cert-manager Secret
}

// keyIDAlphabet avoids visually ambiguous characters (0/O, 1/l/I) since a
// keyID is sometimes typed or read aloud when troubleshooting a cluster.
const keyIDAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

func randomKeyID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, v := range b {
		out[i] = keyIDAlphabet[int(v)%len(keyIDAlphabet)]
	}
	return string(out), nil
}

// CreateEAB generates a new EAB credential: a public keyID and a 32-byte HMAC
// key. The HMAC key is returned once, in CreateEABResult, and stored only
// encrypted (with the same master key that protects every private key goca
// holds) - goca can verify signatures made with it, but never displays it
// again.
func (s *Service) CreateEAB(ctx context.Context, in CreateEABInput) (*CreateEABResult, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, errors.New("a name is required")
	}
	profile := strings.TrimSpace(in.Profile)
	if profile == "" {
		profile = string(pki.ProfileServer)
	}
	// Validate now rather than at the first finalize: an unknown profile used
	// to be stored as-is and then fail every order with a 500, long after the
	// credential was handed to a cluster.
	parsed, err := pki.ParseProfile(profile)
	if err != nil {
		return nil, err
	}
	// ACME issues leaf certificates to whoever holds the credential. An
	// intermediate-ca profile would hand every bootstrapped account a CA that
	// can sign for any name, with no administrator involved per issuance.
	if parsed == pki.ProfileIntermCA {
		return nil, errors.New(`the "intermediate-ca" profile cannot be used for ACME; ` +
			`ACME issues leaf certificates only`)
	}
	profile = string(parsed)

	domains, err := normalizeDomainPatterns(in.AllowedDomains)
	if err != nil {
		return nil, err
	}
	switch {
	case len(domains) == 0 && !in.AllowAnyDomain:
		return nil, errors.New("no allowed domains given: accounts bootstrapped with this credential could " +
			"obtain a certificate for any hostname, since goca's ACME performs no domain-control check. " +
			"Restrict it (e.g. '*.cluster-a.internal'), or explicitly allow any domain")
	case len(domains) > 0 && in.AllowAnyDomain:
		return nil, errors.New("give allowed domains or allow any domain, not both")
	}

	var caID *int64
	if ref := strings.TrimSpace(in.CARef); ref != "" {
		ca, err := s.caSvc.ResolveCA(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("authority %q: %w", ref, err)
		}
		id := ca.ID
		caID = &id
	}

	keyID, err := randomKeyID(20)
	if err != nil {
		return nil, err
	}
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, err
	}
	hmacB64 := base64.RawURLEncoding.EncodeToString(hmacKey)
	hmacEnc, err := s.caSvc.Box().Encrypt(hmacKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt HMAC key: %w", err)
	}

	var expires *time.Time
	if in.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, in.ExpiresInDays)
		expires = &t
	}

	cred, err := s.st.CreateEABCred(ctx, &store.EABCred{
		KeyID:          keyID,
		HMACKeyEnc:     hmacEnc,
		Name:           name,
		CAID:           caID,
		Profile:        profile,
		Days:           in.Days,
		AllowedDomains: domains,
		MaxAccounts:    in.MaxAccounts,
		ExpiresAt:      expires,
		CreatedBy:      in.Actor,
		CreatedAt:      time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, in.Actor, "acme.eab.create", name,
		fmt.Sprintf("key_id=%s profile=%s domains=%s", keyID, profile, describeDomains(domains)))
	return &CreateEABResult{Cred: cred, HMACKeyB64: hmacB64}, nil
}

// ListEAB lists every credential.
func (s *Service) ListEAB(ctx context.Context) ([]*store.EABCred, error) {
	return s.st.ListEABCreds(ctx)
}

// GetEAB fetches one credential by id.
func (s *Service) GetEAB(ctx context.Context, id int64) (*store.EABCred, error) {
	return s.st.GetEABCred(ctx, id)
}

// ResolveEAB finds a credential by id, keyID, or - when it names exactly one
// credential - display name. Names have no uniqueness constraint, so a name
// that matches more than one credential is reported rather than guessed at.
func (s *Service) ResolveEAB(ctx context.Context, ref string) (*store.EABCred, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("an id, key id or name is required")
	}
	if c, err := s.st.GetEABCredByKeyID(ctx, ref); err == nil {
		return c, nil
	}
	var id int64
	if _, err := fmt.Sscanf(ref, "%d", &id); err == nil {
		if c, err := s.st.GetEABCred(ctx, id); err == nil {
			return c, nil
		}
	}
	all, err := s.st.ListEABCreds(ctx)
	if err != nil {
		return nil, err
	}
	var matches []*store.EABCred
	for _, c := range all {
		if strings.EqualFold(c.Name, ref) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, fmt.Errorf("no EAB credential matches %q", ref)
	default:
		return nil, fmt.Errorf("%q names %d EAB credentials; use its id or key id instead", ref, len(matches))
	}
}

// SetEABDisabled enables or disables a credential. Disabling stops it from
// bootstrapping new accounts and - via activeCred, checked on every order and
// finalize - stops every account it already created from obtaining
// certificates until it is re-enabled. That second half is what makes this
// usable as incident response for a leaked HMAC key; see activeCred.
func (s *Service) SetEABDisabled(ctx context.Context, id int64, disabled bool, actor string) error {
	c, err := s.st.GetEABCred(ctx, id)
	if err != nil {
		return err
	}
	if err := s.st.SetEABCredDisabled(ctx, id, disabled); err != nil {
		return err
	}
	action := "acme.eab.enable"
	if disabled {
		action = "acme.eab.disable"
	}
	s.audit(ctx, actor, action, c.Name, "key_id="+c.KeyID)
	return nil
}

// DeleteEAB removes a credential, refusing when accounts still reference it
// so history is never silently lost - disable it instead, or delete those
// accounts first (deactivating an account does not remove it).
func (s *Service) DeleteEAB(ctx context.Context, id int64, actor string) error {
	c, err := s.st.GetEABCred(ctx, id)
	if err != nil {
		return err
	}
	accounts, err := s.st.ListAcmeAccountsByEAB(ctx, id)
	if err != nil {
		return err
	}
	if len(accounts) > 0 {
		return fmt.Errorf("%d ACME account(s) were bootstrapped with %q; disable it instead of deleting, "+
			"or remove those accounts first", len(accounts), c.Name)
	}
	if err := s.st.DeleteEABCred(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, "acme.eab.delete", c.Name, "key_id="+c.KeyID)
	return nil
}

// DeactivateAccount permanently deactivates one ACME account, as an
// administrator. A deactivated account can no longer authenticate any
// request - order, finalize, download or revoke - and per RFC 8555 §7.3.6
// deactivation is final: the client must register again, which needs a
// usable EAB credential.
//
// This is the narrow counterpart to disabling a credential (which cuts off
// every account bootstrapped from it): use it when one account's key is
// compromised but its siblings are fine. Deleting the account instead would
// orphan its orders and the provenance of the certificates they produced.
func (s *Service) DeactivateAccount(ctx context.Context, id int64, actor string) error {
	a, err := s.st.GetAcmeAccount(ctx, id)
	if err != nil {
		return err
	}
	if a.Status == store.AcmeStatusDeactivated {
		return fmt.Errorf("ACME account %d is already deactivated", id)
	}
	if err := s.st.SetAcmeAccountStatus(ctx, id, store.AcmeStatusDeactivated); err != nil {
		return err
	}
	s.audit(ctx, actor, "acme.account.deactivate", fmt.Sprint(id), "by administrator")
	return nil
}

// ListAccounts lists every registered ACME account.
func (s *Service) ListAccounts(ctx context.Context) ([]*store.AcmeAccount, error) {
	return s.st.ListAcmeAccounts(ctx)
}

// GetAccountByID fetches one account by id, for admin/CLI/API/UI use. The
// protocol-level GetAccount (service.go) handles the authenticated ACME
// POST-as-GET/update instead.
func (s *Service) GetAccountByID(ctx context.Context, id int64) (*store.AcmeAccount, error) {
	return s.st.GetAcmeAccount(ctx, id)
}

// ListOrders lists an account's orders.
func (s *Service) ListOrders(ctx context.Context, accountID int64) ([]*store.AcmeOrder, error) {
	return s.st.ListAcmeOrdersByAccount(ctx, accountID)
}
