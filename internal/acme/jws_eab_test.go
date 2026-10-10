package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

type fixedNonce string

func (n fixedNonce) Nonce() (string, error) { return string(n), nil }

// buildEAB signs an externalAccountBinding over accountJWK, optionally with a
// nonce in its protected header - which RFC 8555 §7.3.4 forbids, and which no
// well-behaved client sends, so it can only be tested by constructing one.
func buildEAB(t *testing.T, hmacKey []byte, kid, url string, accountJWK *jose.JSONWebKey, nonce string) []byte {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid).WithHeader("url", url)
	if nonce != "" {
		opts.NonceSource = fixedNonce(nonce)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(accountJWK)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(obj.FullSerialize())
}

func TestVerifyEABRejectsNonce(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := &jose.JSONWebKey{Key: key.Public()}
	hmacKey := make([]byte, 32)
	const kid, url = "kid123", "https://ca.test/acme/new-account"
	lookup := func(k string) ([]byte, bool) { return hmacKey, k == kid }

	if _, err := VerifyEAB(buildEAB(t, hmacKey, kid, url, jwk, ""), url, jwk, lookup); err != nil {
		t.Fatalf("a well-formed EAB was rejected: %v", err)
	}
	_, err := VerifyEAB(buildEAB(t, hmacKey, kid, url, jwk, "some-nonce"), url, jwk, lookup)
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("EAB carrying a nonce: err = %v, want a refusal naming the nonce", err)
	}
}
