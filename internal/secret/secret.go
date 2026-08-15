// Package secret provides authenticated encryption for private keys and other
// sensitive values stored in SQLite or the config file.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Prefix marks a value as encrypted by this package.
const Prefix = "enc:v1:"

// Box encrypts and decrypts values with a 32-byte master key.
type Box struct {
	aead cipher.AEAD
}

// NewBox builds a Box from a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Encrypt returns "enc:v1:<base64(nonce||ciphertext)>".
func (b *Box) Encrypt(plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, plaintext, nil)
	return Prefix + base64.StdEncoding.EncodeToString(ct), nil
}

// EncryptString is a convenience wrapper around Encrypt.
func (b *Box) EncryptString(s string) (string, error) { return b.Encrypt([]byte(s)) }

// Decrypt reverses Encrypt. Values without the prefix are returned unchanged,
// which lets operators drop plaintext into the config by hand.
func (b *Box) Decrypt(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if !strings.HasPrefix(value, Prefix) {
		return []byte(value), nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, Prefix))
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext too short")
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed (wrong master key?): %w", err)
	}
	return pt, nil
}

// DecryptString is a convenience wrapper around Decrypt.
func (b *Box) DecryptString(value string) (string, error) {
	pt, err := b.Decrypt(value)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// IsEncrypted reports whether a stored value carries the encryption prefix.
func IsEncrypted(value string) bool { return strings.HasPrefix(value, Prefix) }
