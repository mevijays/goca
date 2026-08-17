// Package pqcrypt implements the secret manager's envelope encryption: a
// hybrid X25519 + ML-KEM-768 key encapsulation mechanism (NIST FIPS 203)
// wrapping a per-secret-version AES-256-GCM data key.
//
// This is deliberately hybrid, not ML-KEM alone - the same construction
// TLS 1.3 uses for its X25519MLKEM768 group. Security holds as long as
// either primitive holds, so a future cryptanalytic break or implementation
// flaw in ML-KEM cannot by itself expose sealed secrets; pure ML-KEM would
// be a regression against that.
//
// Read docs/secrets.md before assuming "post-quantum" means "replaces AES-256":
// AES-256-GCM is itself already considered post-quantum secure (Grover's
// algorithm only halves its effective key strength), so what ML-KEM adds
// here is specifically public-key envelope encryption - harvest-now,
// decrypt-later resistance on the key-wrapping step, the ability to
// re-wrap data keys on vault-key rotation without re-encrypting payloads,
// and a path to a future write-only role that can seal a secret without
// being able to read it back - not a stronger cipher for the payload
// itself, which was already sound.
package pqcrypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"crypto/aes"
	"crypto/cipher"
)

// Prefix marks a value as sealed by this package, mirroring the enc:v1:
// convention internal/secret already uses for config-file/CA-key values.
// The two are intentionally separate packages: internal/secret's AES-GCM
// box, keyed directly by the master key, continues to protect CA private
// keys and config-file secrets unchanged: this package (and its pqenc:v1:
// prefix) is only for the secret manager's vault-stored secrets.
const Prefix = "pqenc:v1:"

// algHybridX25519MLKEM768 is the only algorithm ID defined so far. It is
// recorded in every envelope so a future algorithm can be introduced
// without breaking ciphertexts already at rest.
const algHybridX25519MLKEM768 = 1

const (
	saltSize       = 32
	kemCTSize      = mlkem.CiphertextSize768
	x25519PubSize  = 32
	gcmNonceSize   = 12
	dekSize        = 32
	gcmTagSize     = 16
	wrappedDEKSize = dekSize + gcmTagSize

	// headerSize is everything before the payload's own nonce+ciphertext:
	// alg ‖ salt ‖ mlkemCT ‖ x25519EphPub ‖ wrapNonce ‖ wrappedDEK.
	headerSize = 1 + saltSize + kemCTSize + x25519PubSize + gcmNonceSize + wrappedDEKSize
)

// hkdfSalt is fixed and namespaces vault-keypair derivation from the master
// key; the info strings separate the two independent keys drawn from it.
const (
	hkdfSalt       = "goca/pq/vault/v1"
	infoMLKEMSeed  = "mlkem768-seed"
	infoX25519Priv = "x25519-priv"
	infoDEKWrap    = "dek-wrap"
)

// Vault holds a hybrid X25519 + ML-KEM-768 keypair.
type Vault struct {
	mlkemDK    *mlkem.DecapsulationKey768
	x25519Priv *ecdh.PrivateKey
}

// DeriveVault deterministically derives the vault keypair from a 32-byte
// master key via HKDF-SHA256. The same master key always yields the same
// vault keypair, so a restart needs no separate unseal step and no new key
// material to back up beyond what docs/setup.md already documents: config.yaml
// and the database, together. The trade-off is the same one that already
// applies to CA private keys - anyone holding the master key can decrypt
// everything sealed with it.
func DeriveVault(masterKey []byte) (*Vault, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("pqcrypt: master key must be 32 bytes, got %d", len(masterKey))
	}
	mlkemSeed, err := hkdf.Key(sha256.New, masterKey, []byte(hkdfSalt), infoMLKEMSeed, mlkem.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: derive ML-KEM seed: %w", err)
	}
	dk, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: derive ML-KEM key: %w", err)
	}
	x25519Seed, err := hkdf.Key(sha256.New, masterKey, []byte(hkdfSalt), infoX25519Priv, 32)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: derive X25519 seed: %w", err)
	}
	xPriv, err := ecdh.X25519().NewPrivateKey(x25519Seed)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: derive X25519 key: %w", err)
	}
	return &Vault{mlkemDK: dk, x25519Priv: xPriv}, nil
}

// Seal encrypts plaintext, authenticating aad alongside it (Open must be
// given the exact same aad bytes to succeed). aad is typically something
// like "goca/secret/v1|<secretID>|<version>", binding the ciphertext to
// where it is stored so it cannot be copied to a different secret or
// version and still decrypt. Returns a self-describing "pqenc:v1:" envelope,
// safe to store directly in a TEXT column.
func (v *Vault) Seal(plaintext, aad []byte) (string, error) {
	ek := v.mlkemDK.EncapsulationKey()
	mlkemShared, mlkemCT := ek.Encapsulate()
	defer zero(mlkemShared)

	xEphPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("pqcrypt: generate ephemeral X25519 key: %w", err)
	}
	x25519Shared, err := xEphPriv.ECDH(v.x25519Priv.PublicKey())
	if err != nil {
		return "", fmt.Errorf("pqcrypt: X25519 exchange: %w", err)
	}
	defer zero(x25519Shared)

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("pqcrypt: generate salt: %w", err)
	}

	kek, err := wrapKey(mlkemShared, x25519Shared, salt)
	if err != nil {
		return "", err
	}
	defer zero(kek)
	kekAEAD, err := newGCM(kek)
	if err != nil {
		return "", err
	}

	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return "", fmt.Errorf("pqcrypt: generate data key: %w", err)
	}
	defer zero(dek)

	wrapNonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(wrapNonce); err != nil {
		return "", fmt.Errorf("pqcrypt: generate nonce: %w", err)
	}
	wrappedDEK := kekAEAD.Seal(nil, wrapNonce, dek, aad)

	dekAEAD, err := newGCM(dek)
	if err != nil {
		return "", err
	}
	payloadNonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(payloadNonce); err != nil {
		return "", fmt.Errorf("pqcrypt: generate nonce: %w", err)
	}
	payloadCT := dekAEAD.Seal(nil, payloadNonce, plaintext, aad)

	var buf bytes.Buffer
	buf.Grow(headerSize + gcmNonceSize + len(payloadCT))
	buf.WriteByte(algHybridX25519MLKEM768)
	buf.Write(salt)
	buf.Write(mlkemCT)
	buf.Write(xEphPriv.PublicKey().Bytes())
	buf.Write(wrapNonce)
	buf.Write(wrappedDEK)
	buf.Write(payloadNonce)
	buf.Write(payloadCT)

	return Prefix + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// SealString is a convenience wrapper around Seal for string plaintext.
func (v *Vault) SealString(s string, aad []byte) (string, error) {
	return v.Seal([]byte(s), aad)
}

// Open reverses Seal. It fails if envelope was tampered with, was sealed
// under a different vault keypair, or aad does not match what Seal was
// given.
func (v *Vault) Open(envelope string, aad []byte) ([]byte, error) {
	if !strings.HasPrefix(envelope, Prefix) {
		return nil, errors.New("pqcrypt: not a pqenc:v1: envelope")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, Prefix))
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: decode envelope: %w", err)
	}
	if len(raw) < headerSize {
		return nil, errors.New("pqcrypt: envelope too short")
	}
	if raw[0] != algHybridX25519MLKEM768 {
		return nil, fmt.Errorf("pqcrypt: unsupported algorithm %d", raw[0])
	}

	off := 1
	salt := raw[off : off+saltSize]
	off += saltSize
	mlkemCT := raw[off : off+kemCTSize]
	off += kemCTSize
	xEphPub := raw[off : off+x25519PubSize]
	off += x25519PubSize
	wrapNonce := raw[off : off+gcmNonceSize]
	off += gcmNonceSize
	wrappedDEK := raw[off : off+wrappedDEKSize]
	off += wrappedDEKSize
	payloadNonce := raw[off : off+gcmNonceSize]
	off += gcmNonceSize
	payloadCT := raw[off:]

	mlkemShared, err := v.mlkemDK.Decapsulate(mlkemCT)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: ML-KEM decapsulate: %w", err)
	}
	defer zero(mlkemShared)

	xPub, err := ecdh.X25519().NewPublicKey(xEphPub)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: parse ephemeral X25519 key: %w", err)
	}
	x25519Shared, err := v.x25519Priv.ECDH(xPub)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: X25519 exchange: %w", err)
	}
	defer zero(x25519Shared)

	kek, err := wrapKey(mlkemShared, x25519Shared, salt)
	if err != nil {
		return nil, err
	}
	defer zero(kek)
	kekAEAD, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := kekAEAD.Open(nil, wrapNonce, wrappedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: unwrap data key failed (wrong vault key, tampered data, or mismatched aad): %w", err)
	}
	defer zero(dek)

	dekAEAD, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := dekAEAD.Open(nil, payloadNonce, payloadCT, aad)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: decrypt failed (tampered data or mismatched aad): %w", err)
	}
	return plaintext, nil
}

// OpenString is a convenience wrapper around Open for string plaintext.
func (v *Vault) OpenString(envelope string, aad []byte) (string, error) {
	pt, err := v.Open(envelope, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// IsEnvelope reports whether value carries the pqenc:v1: prefix.
func IsEnvelope(value string) bool { return strings.HasPrefix(value, Prefix) }

// wrapKey derives the AES-256 key that wraps (or unwraps) the per-message
// data key from the two independent shared secrets, so the wrapping key
// depends on both the ML-KEM and the X25519 exchange - a break in either
// alone is not enough to recover it.
func wrapKey(mlkemShared, x25519Shared, salt []byte) ([]byte, error) {
	combined := make([]byte, 0, len(mlkemShared)+len(x25519Shared))
	combined = append(combined, mlkemShared...)
	combined = append(combined, x25519Shared...)
	defer zero(combined)
	kek, err := hkdf.Key(sha256.New, combined, salt, infoDEKWrap, 32)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: derive wrapping key: %w", err)
	}
	return kek, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pqcrypt: %w", err)
	}
	return aead, nil
}

// zero best-effort wipes key material from memory once it's no longer
// needed. Go's GC means this is defense-in-depth, not a guarantee - but it
// costs nothing and shrinks the window a copy could be scraped from a heap
// dump or paged-out memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
