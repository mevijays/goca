package pqcrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testVault(t *testing.T) *Vault {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	v, err := DeriveVault(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDeriveVaultRejectsWrongKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := DeriveVault(make([]byte, n)); err == nil {
			t.Errorf("DeriveVault accepted a %d-byte key, want an error", n)
		}
	}
}

func TestDeriveVaultIsDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	v1, err := DeriveVault(key)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := DeriveVault(key)
	if err != nil {
		t.Fatal(err)
	}
	// Same master key must yield a vault that can decrypt the other's
	// ciphertexts - this is what lets goca restart unattended.
	env, err := v1.Seal([]byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := v2.Open(env, []byte("aad"))
	if err != nil {
		t.Fatalf("second derivation could not open the first's envelope: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	v := testVault(t)
	cases := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("hunter2"),
		bytes.Repeat([]byte("x"), 100_000), // exercise a large payload, not just short KV values
		{0x00, 0x01, 0xFF, 0xFE},           // binary content, not just text
	}
	for _, pt := range cases {
		env, err := v.Seal(pt, []byte("goca/secret/v1|1|1"))
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", len(pt), err)
		}
		if !strings.HasPrefix(env, Prefix) {
			t.Fatalf("envelope missing %q prefix: %q", Prefix, env[:min(20, len(env))])
		}
		if !IsEnvelope(env) {
			t.Error("IsEnvelope returned false for a real envelope")
		}
		got, err := v.Open(env, []byte("goca/secret/v1|1|1"))
		if err != nil {
			t.Fatalf("Open(%d bytes): %v", len(pt), err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(pt))
		}
	}
}

func TestSealIsNonDeterministic(t *testing.T) {
	v := testVault(t)
	env1, err := v.Seal([]byte("same plaintext"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	env2, err := v.Seal([]byte("same plaintext"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if env1 == env2 {
		t.Error("sealing the same plaintext twice produced identical ciphertext - ephemeral randomness is not being used")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	v := testVault(t)
	env, err := v.Seal([]byte("secret value"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := decodeForTest(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, headerSize, len(raw) - 1} {
		tampered := append([]byte(nil), raw...)
		tampered[i] ^= 0xFF
		env := Prefix + encodeForTest(tampered)
		if _, err := v.Open(env, []byte("aad")); err == nil {
			t.Errorf("Open accepted a ciphertext tampered at byte %d", i)
		}
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	v := testVault(t)
	env, err := v.Seal([]byte("secret value"), []byte("goca/secret/v1|1|1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Open(env, []byte("goca/secret/v1|1|2")); err == nil {
		t.Error("Open accepted a ciphertext under the wrong AAD (version 2 instead of 1) - a ciphertext could be relocated to a different version")
	}
	if _, err := v.Open(env, []byte("goca/secret/v1|2|1")); err == nil {
		t.Error("Open accepted a ciphertext under the wrong AAD (secret 2 instead of 1) - a ciphertext could be relocated to a different secret")
	}
	if _, err := v.Open(env, nil); err == nil {
		t.Error("Open accepted a ciphertext with empty AAD when it was sealed with non-empty AAD")
	}
}

func TestOpenRejectsWrongVault(t *testing.T) {
	v1 := testVault(t)
	v2 := testVault(t)
	env, err := v1.Seal([]byte("secret value"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Open(env, []byte("aad")); err == nil {
		t.Error("a different vault keypair could open the first vault's envelope")
	}
}

func TestOpenRejectsMalformedInput(t *testing.T) {
	v := testVault(t)
	cases := []string{
		"",
		"not an envelope at all",
		"pqenc:v1:",
		"pqenc:v1:not-valid-base64!!!",
		"pqenc:v1:" + encodeForTest([]byte{1, 2, 3}), // valid base64, way too short
		"enc:v1:AAAA", // internal/secret's prefix, not this package's
	}
	for _, c := range cases {
		if _, err := v.Open(c, nil); err == nil {
			t.Errorf("Open(%q) succeeded, want an error", c)
		}
	}
}

func TestOpenRejectsUnsupportedAlgorithm(t *testing.T) {
	v := testVault(t)
	env, err := v.Seal([]byte("x"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := decodeForTest(env)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 0xFF
	bad := Prefix + encodeForTest(raw)
	if _, err := v.Open(bad, []byte("aad")); err == nil {
		t.Error("Open accepted an envelope with an unrecognized algorithm byte")
	}
}

func TestSealStringOpenString(t *testing.T) {
	v := testVault(t)
	env, err := v.SealString("hunter2", []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.OpenString(env, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestIsEnvelope(t *testing.T) {
	if IsEnvelope("plaintext") {
		t.Error("IsEnvelope(plaintext) = true")
	}
	if IsEnvelope("enc:v1:xxx") {
		t.Error("IsEnvelope should not match internal/secret's enc:v1: prefix")
	}
	if !IsEnvelope("pqenc:v1:xxx") {
		t.Error("IsEnvelope(pqenc:v1:xxx) = false")
	}
}

func decodeForTest(env string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env, Prefix))
}

func encodeForTest(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
