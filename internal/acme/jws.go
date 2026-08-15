package acme

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// accountAlgs are the signature algorithms accepted for account-key JWS
// (everything except the inner externalAccountBinding, which is always
// HS256). RFC 8555 does not mandate a specific set; this covers every key
// type goca itself can issue plus RSA, which is what most ACME client
// libraries default to.
var accountAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.PS256, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

var eabAlgs = []jose.SignatureAlgorithm{jose.HS256}

// ParsedJWS is an inbound ACME request after structural parsing. Its
// signature has NOT been verified yet - the caller must call Verify with the
// appropriate key once it knows which key that is (the embedded jwk for
// new-account, or an existing account's stored key resolved from kid).
type ParsedJWS struct {
	Payload []byte // raw, still-undecoded-as-JSON payload bytes (may be empty for POST-as-GET)
	KeyID   string // "kid" protected header, set for every request except new-account
	JWK     *jose.JSONWebKey
	Nonce   string
	URL     string // "url" protected header - ACME-specific, RFC 8555 §6.4

	raw *jose.JSONWebSignature
}

// ParseJWS parses a JWS in compact or flattened-JSON serialization from an
// ACME request body. It enforces the structural rules RFC 8555 §6.2 layers on
// top of plain JOSE: exactly one signature, no unprotected header (every
// field that matters must be signed), and exactly one of jwk/kid.
func ParseJWS(body []byte) (*ParsedJWS, error) {
	obj, err := jose.ParseSigned(string(body), accountAlgs)
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}
	if len(obj.Signatures) != 1 {
		return nil, errors.New("a JWS must carry exactly one signature")
	}
	sig := obj.Signatures[0]

	// ACME forbids an unprotected header entirely: anything not signed can't
	// be trusted, and the spec removes the ambiguity by disallowing it.
	if sig.Unprotected.KeyID != "" || sig.Unprotected.JSONWebKey != nil ||
		sig.Unprotected.Nonce != "" || len(sig.Unprotected.ExtraHeaders) > 0 {
		return nil, errors.New("unprotected JWS headers are not permitted")
	}

	hdr := sig.Protected
	if hdr.KeyID != "" && hdr.JSONWebKey != nil {
		return nil, errors.New("a JWS must not carry both jwk and kid")
	}
	if hdr.KeyID == "" && hdr.JSONWebKey == nil {
		return nil, errors.New("a JWS must carry jwk or kid")
	}
	urlVal, _ := hdr.ExtraHeaders["url"].(string)
	if urlVal == "" {
		return nil, errors.New(`a JWS must carry a "url" protected header`)
	}

	return &ParsedJWS{
		KeyID: hdr.KeyID,
		JWK:   hdr.JSONWebKey,
		Nonce: hdr.Nonce,
		URL:   urlVal,
		raw:   obj,
	}, nil
}

// Verify checks the signature against key (an *rsa.PublicKey, *ecdsa.PublicKey,
// ed25519.PublicKey, or *jose.JSONWebKey) and, on success, decodes the payload.
func (p *ParsedJWS) Verify(key any) error {
	payload, err := p.raw.Verify(key)
	if err != nil {
		return fmt.Errorf("JWS signature verification failed: %w", err)
	}
	p.Payload = payload
	return nil
}

// DecodePayload JSON-decodes the (already-verified) payload into v. An empty
// payload - the "POST-as-GET" convention (§6.3) used to fetch a resource
// without submitting data - decodes into the zero value.
func (p *ParsedJWS) DecodePayload(v any) error {
	if len(p.Payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(p.Payload, v); err != nil {
		return fmt.Errorf("decode JWS payload: %w", err)
	}
	return nil
}

// IsPostAsGet reports whether this request used an empty payload to fetch a
// resource rather than submit data (§6.3).
func (p *ParsedJWS) IsPostAsGet() bool { return len(p.Payload) == 0 }

// VerifyEAB validates a new-account request's externalAccountBinding object
// against the credential lookupHMAC resolves, per RFC 8555 §7.3.4: the inner
// JWS's "url" must match the outer request's URL, its signature must verify
// under the credential's HMAC key, and its payload - the account's own public
// key - must exactly match the JWK the outer JWS was signed with. That three-
// way binding (server-issued secret + outer signature + inner signature all
// agreeing on one account key) is the entire trust decision an ACME account
// gets in this implementation.
//
// lookupHMAC is called with the inner JWS's "kid" (the EAB keyID) and must
// return the credential's decrypted HMAC key. keyID is always returned, even
// on error, so the caller can audit-log which credential was attempted.
func VerifyEAB(eabJSON []byte, outerURL string, accountJWK *jose.JSONWebKey,
	lookupHMAC func(keyID string) ([]byte, bool)) (keyID string, err error) {

	if len(eabJSON) == 0 {
		return "", errors.New("no externalAccountBinding was supplied")
	}
	obj, err := jose.ParseSigned(string(eabJSON), eabAlgs)
	if err != nil {
		return "", fmt.Errorf("parse externalAccountBinding: %w", err)
	}
	if len(obj.Signatures) != 1 {
		return "", errors.New("externalAccountBinding must carry exactly one signature")
	}
	hdr := obj.Signatures[0].Protected
	keyID = hdr.KeyID
	if keyID == "" {
		return "", errors.New("externalAccountBinding is missing kid")
	}
	if hdr.JSONWebKey != nil {
		return keyID, errors.New("externalAccountBinding must not carry a jwk header")
	}
	if urlVal, _ := hdr.ExtraHeaders["url"].(string); urlVal != outerURL {
		return keyID, errors.New("externalAccountBinding url does not match the request url")
	}

	hmacKey, ok := lookupHMAC(keyID)
	if !ok {
		return keyID, fmt.Errorf("unknown external account binding key id %q", keyID)
	}
	payload, err := obj.Verify(hmacKey)
	if err != nil {
		return keyID, fmt.Errorf("externalAccountBinding signature is invalid: %w", err)
	}

	var boundJWK jose.JSONWebKey
	if err := json.Unmarshal(payload, &boundJWK); err != nil {
		return keyID, fmt.Errorf("externalAccountBinding payload is not a JWK: %w", err)
	}
	want, err := accountJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return keyID, fmt.Errorf("compute account key thumbprint: %w", err)
	}
	got, err := boundJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return keyID, fmt.Errorf("compute bound key thumbprint: %w", err)
	}
	if !bytes.Equal(want, got) {
		return keyID, errors.New("externalAccountBinding does not bind the account's own key")
	}
	return keyID, nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of a JWK, hex-encoded,
// used as the stable identifier for detecting a re-registration of the same
// account key (RFC 8555 §7.3.1).
func Thumbprint(jwk *jose.JSONWebKey) (string, error) {
	b, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
