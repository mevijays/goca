// Package pki implements the certificate authority: key generation, CSR
// handling, CA creation, issuance, revocation and CRL production. It uses only
// the Go standard library crypto stack, so no OpenSSL runtime is required.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// KeyType names the algorithm and size of a generated private key.
type KeyType string

// Supported key types.
const (
	KeyRSA2048 KeyType = "rsa-2048"
	KeyRSA3072 KeyType = "rsa-3072"
	KeyRSA4096 KeyType = "rsa-4096"
	KeyECP256  KeyType = "ec-p256"
	KeyECP384  KeyType = "ec-p384"
	KeyECP521  KeyType = "ec-p521"
	KeyEd25519 KeyType = "ed25519"
)

// KeyTypes lists every selectable key type, in menu order.
var KeyTypes = []KeyType{KeyRSA2048, KeyRSA3072, KeyRSA4096, KeyECP256, KeyECP384, KeyECP521, KeyEd25519}

// ParseKeyType normalises user input such as "RSA 4096", "rsa4096", "p-256".
func ParseKeyType(s string) (KeyType, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.NewReplacer(" ", "-", "_", "-").Replace(n)
	switch n {
	case "", "default":
		return KeyRSA2048, nil
	case "rsa", "rsa-2048", "rsa2048":
		return KeyRSA2048, nil
	case "rsa-3072", "rsa3072":
		return KeyRSA3072, nil
	case "rsa-4096", "rsa4096":
		return KeyRSA4096, nil
	case "ec", "ecdsa", "ec-p256", "ecp256", "p-256", "p256", "prime256v1", "secp256r1":
		return KeyECP256, nil
	case "ec-p384", "ecp384", "p-384", "p384", "secp384r1":
		return KeyECP384, nil
	case "ec-p521", "ecp521", "p-521", "p521", "secp521r1":
		return KeyECP521, nil
	case "ed25519", "ed-25519":
		return KeyEd25519, nil
	}
	return "", fmt.Errorf("unsupported key type %q (valid: %s)", s, joinKeyTypes())
}

func joinKeyTypes() string {
	parts := make([]string, len(KeyTypes))
	for i, k := range KeyTypes {
		parts[i] = string(k)
	}
	return strings.Join(parts, ", ")
}

// GenerateKey creates a fresh private key of the requested type.
func GenerateKey(kt KeyType) (crypto.PrivateKey, error) {
	switch kt {
	case KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case KeyRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case KeyECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyECP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case KeyEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("unsupported key type %q", kt)
}

// EncodePrivateKeyPEM marshals a private key as unencrypted PKCS#8 PEM.
func EncodePrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM accepts PKCS#8, PKCS#1 ("RSA PRIVATE KEY") or SEC1
// ("EC PRIVATE KEY") PEM - i.e. anything openssl commonly emits.
func ParsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			return x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("encrypted private keys are not supported; decrypt it first " +
				"(openssl pkcs8 -topk8 -nocrypt -in enc.key -out plain.key)")
		}
	}
	return nil, errors.New("no private key found in PEM input")
}

// PublicKeyOf extracts the public half of a private key.
func PublicKeyOf(key crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	}
	return nil, fmt.Errorf("unsupported private key type %T", key)
}

// KeyTypeOf reports the KeyType of an existing public or private key.
func KeyTypeOf(key any) KeyType {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return rsaKeyType(k.N.BitLen())
	case *rsa.PublicKey:
		return rsaKeyType(k.N.BitLen())
	case *ecdsa.PrivateKey:
		return ecKeyType(k.Curve)
	case *ecdsa.PublicKey:
		return ecKeyType(k.Curve)
	case ed25519.PrivateKey, ed25519.PublicKey:
		return KeyEd25519
	}
	return KeyType("unknown")
}

func rsaKeyType(bits int) KeyType {
	switch {
	case bits >= 4096:
		return KeyRSA4096
	case bits >= 3072:
		return KeyRSA3072
	default:
		return KeyType(fmt.Sprintf("rsa-%d", bits))
	}
}

func ecKeyType(c elliptic.Curve) KeyType {
	switch c {
	case elliptic.P256():
		return KeyECP256
	case elliptic.P384():
		return KeyECP384
	case elliptic.P521():
		return KeyECP521
	}
	return KeyType("ec-unknown")
}

// signatureAlgorithmFor picks a sane signature algorithm for an issuer key.
// Ed25519 has exactly one; RSA/ECDSA scale the hash with the key size.
func signatureAlgorithmFor(issuerKey crypto.PrivateKey) x509.SignatureAlgorithm {
	switch k := issuerKey.(type) {
	case *rsa.PrivateKey:
		switch {
		case k.N.BitLen() >= 4096:
			return x509.SHA512WithRSA
		case k.N.BitLen() >= 3072:
			return x509.SHA384WithRSA
		default:
			return x509.SHA256WithRSA
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		case elliptic.P384():
			return x509.ECDSAWithSHA384
		default:
			return x509.ECDSAWithSHA256
		}
	case ed25519.PrivateKey:
		return x509.PureEd25519
	}
	return x509.UnknownSignatureAlgorithm
}

// EncodeCertPEM wraps DER certificate bytes in PEM.
func EncodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ParseCertPEM decodes the first certificate in a PEM blob.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	return nil, errors.New("no CERTIFICATE block found in PEM input")
}
