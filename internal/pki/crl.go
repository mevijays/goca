package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// RevocationReason codes from RFC 5280 section 5.3.1.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
	ReasonRemoveFromCRL        = 8
	ReasonPrivilegeWithdrawn   = 9
	ReasonAACompromise         = 10
)

// ReasonNames maps reason codes to human labels for the UI and CLI.
var ReasonNames = map[int]string{
	ReasonUnspecified:          "unspecified",
	ReasonKeyCompromise:        "key compromise",
	ReasonCACompromise:         "CA compromise",
	ReasonAffiliationChanged:   "affiliation changed",
	ReasonSuperseded:           "superseded",
	ReasonCessationOfOperation: "cessation of operation",
	ReasonCertificateHold:      "certificate hold",
	ReasonPrivilegeWithdrawn:   "privilege withdrawn",
	ReasonAACompromise:         "AA compromise",
}

// ReasonName renders a revocation reason code.
func ReasonName(code int) string {
	if n, ok := ReasonNames[code]; ok {
		return n
	}
	return fmt.Sprintf("code %d", code)
}

// ParseReason accepts a numeric code or a name such as "keyCompromise".
func ParseReason(s string) (int, error) {
	switch normalise(s) {
	case "", "unspecified":
		return ReasonUnspecified, nil
	case "keycompromise", "key-compromise", "1":
		return ReasonKeyCompromise, nil
	case "cacompromise", "ca-compromise", "2":
		return ReasonCACompromise, nil
	case "affiliationchanged", "affiliation-changed", "3":
		return ReasonAffiliationChanged, nil
	case "superseded", "4":
		return ReasonSuperseded, nil
	case "cessationofoperation", "cessation-of-operation", "5":
		return ReasonCessationOfOperation, nil
	case "certificatehold", "certificate-hold", "hold", "6":
		return ReasonCertificateHold, nil
	case "privilegewithdrawn", "privilege-withdrawn", "9":
		return ReasonPrivilegeWithdrawn, nil
	case "aacompromise", "aa-compromise", "10":
		return ReasonAACompromise, nil
	case "0":
		return ReasonUnspecified, nil
	}
	return 0, fmt.Errorf("unknown revocation reason %q", s)
}

// RevokedEntry pairs a serial with the time and reason of revocation.
type RevokedEntry struct {
	SerialHex string
	RevokedAt time.Time
	Reason    int
}

// CRLParams describes a CRL to be issued.
type CRLParams struct {
	Issuer    *x509.Certificate
	IssuerKey crypto.PrivateKey
	Number    int64
	ValidDays int
	Revoked   []RevokedEntry
}

// CreateCRL produces a DER and PEM encoded certificate revocation list.
func CreateCRL(p CRLParams) (der []byte, pemBytes []byte, err error) {
	if p.Issuer == nil || p.IssuerKey == nil {
		return nil, nil, errors.New("issuer certificate and key are required")
	}
	signer, ok := p.IssuerKey.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("issuer key does not implement crypto.Signer")
	}
	if p.ValidDays <= 0 {
		p.ValidDays = 7
	}
	now := time.Now().UTC()
	entries := make([]x509.RevocationListEntry, 0, len(p.Revoked))
	for _, r := range p.Revoked {
		serial, ok := SerialFromHex(r.SerialHex)
		if !ok {
			return nil, nil, fmt.Errorf("bad serial %q in revocation list", r.SerialHex)
		}
		at := r.RevokedAt
		if at.IsZero() {
			at = now
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: at.UTC(),
			ReasonCode:     r.Reason,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(p.Number),
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(0, 0, p.ValidDays),
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        signatureAlgorithmFor(p.IssuerKey),
	}
	der, err = x509.CreateRevocationList(rand.Reader, tmpl, p.Issuer, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("create CRL: %w", err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}
