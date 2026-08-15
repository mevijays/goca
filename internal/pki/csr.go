package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// CSRRequest describes a certificate signing request to be generated.
type CSRRequest struct {
	Subject Subject
	SANs    SANSet
	KeyType KeyType
}

// CSRResult carries a generated CSR together with its new private key.
type CSRResult struct {
	CSRPEM        []byte
	PrivateKeyPEM []byte
	PrivateKey    crypto.PrivateKey
	KeyType       KeyType
}

// GenerateCSR creates a private key and a matching CSR.
func GenerateCSR(req CSRRequest) (*CSRResult, error) {
	if err := req.Subject.Validate(); err != nil {
		return nil, err
	}
	kt := req.KeyType
	if kt == "" {
		kt = KeyRSA2048
	}
	key, err := GenerateKey(kt)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	csrPEM, err := CSRFromKey(key, req)
	if err != nil {
		return nil, err
	}
	keyPEM, err := EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	return &CSRResult{CSRPEM: csrPEM, PrivateKeyPEM: keyPEM, PrivateKey: key, KeyType: kt}, nil
}

// CSRFromKey builds a CSR for an existing private key.
func CSRFromKey(key crypto.PrivateKey, req CSRRequest) ([]byte, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}
	tmpl := &x509.CertificateRequest{
		Subject:            req.Subject.PKIX(),
		SignatureAlgorithm: signatureAlgorithmFor(key),
		DNSNames:           req.SANs.DNS,
		IPAddresses:        req.SANs.IPs,
		EmailAddresses:     req.SANs.Emails,
		URIs:               req.SANs.URIs,
	}
	if req.Subject.EmailAddress != "" {
		tmpl.EmailAddresses = appendUnique(tmpl.EmailAddresses, req.Subject.EmailAddress)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// ParseCSR decodes and verifies a PEM (or raw DER) certificate request.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("expected a CERTIFICATE REQUEST PEM block, got %q", block.Type)
		}
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}
	return csr, nil
}

// CSRInfo is a display-friendly summary of a certificate request.
type CSRInfo struct {
	Subject            string   `json:"subject"`
	CommonName         string   `json:"common_name"`
	SANs               []string `json:"sans"`
	KeyType            string   `json:"key_type"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
}

// DescribeCSR summarises a parsed CSR.
func DescribeCSR(csr *x509.CertificateRequest) CSRInfo {
	return CSRInfo{
		Subject:            DNString(csr.Subject),
		CommonName:         csr.Subject.CommonName,
		SANs:               sanStringsFrom(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs),
		KeyType:            string(KeyTypeOf(csr.PublicKey)),
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
	}
}

// KeyMatchesCSR verifies that a private key corresponds to a CSR's public key.
// It is used when a user uploads both a CSR and its key for storage.
func KeyMatchesCSR(key crypto.PrivateKey, csr *x509.CertificateRequest) error {
	pub, err := PublicKeyOf(key)
	if err != nil {
		return err
	}
	return samePublicKey(pub, csr.PublicKey)
}

// KeyMatchesCert verifies that a private key belongs to a certificate.
func KeyMatchesCert(key crypto.PrivateKey, cert *x509.Certificate) error {
	pub, err := PublicKeyOf(key)
	if err != nil {
		return err
	}
	return samePublicKey(pub, cert.PublicKey)
}

func samePublicKey(a, b crypto.PublicKey) error {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ae, ok := a.(equaler)
	if !ok {
		return errors.New("unsupported public key type for comparison")
	}
	if !ae.Equal(b) {
		return errors.New("private key does not match the public key")
	}
	return nil
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
