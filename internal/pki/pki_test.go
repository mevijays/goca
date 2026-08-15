package pki

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestCreateRootCAAndSign(t *testing.T) {
	root, err := CreateCA(CAParams{
		Subject: Subject{CommonName: "Test Root CA", Organization: "Example", Country: "IN"},
		KeyType: KeyECP256,
		Days:    3650,
		PathLen: 1,
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	if !root.Certificate.IsCA {
		t.Fatal("root certificate is not marked as a CA")
	}
	if root.Certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("root certificate lacks keyCertSign")
	}
	if len(root.Certificate.SubjectKeyId) == 0 {
		t.Fatal("root certificate has no subject key identifier")
	}

	// Intermediate signed by the root.
	inter, err := CreateCA(CAParams{
		Subject:   Subject{CommonName: "Test Issuing CA", Organization: "Example"},
		KeyType:   KeyECP256,
		Days:      1825,
		PathLen:   0,
		Parent:    root.Certificate,
		ParentKey: root.PrivateKey,
	})
	if err != nil {
		t.Fatalf("CreateCA intermediate: %v", err)
	}

	// End-entity signed by the intermediate.
	gen, err := GenerateCSR(CSRRequest{
		Subject: Subject{CommonName: "app.example.test", Organization: "Example"},
		KeyType: KeyRSA2048,
	})
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	csr, err := ParseCSR(gen.CSRPEM)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	sans, err := ParseSANs([]string{"app.example.test, 10.0.0.5", "IP:192.168.1.1", "admin@example.test"})
	if err != nil {
		t.Fatalf("ParseSANs: %v", err)
	}
	leaf, err := Sign(SignParams{
		CSR:         csr,
		Issuer:      inter.Certificate,
		IssuerKey:   inter.PrivateKey,
		Profile:     ProfileServerCli,
		Days:        90,
		SANOverride: &sans,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := len(leaf.Certificate.DNSNames); got != 1 {
		t.Errorf("expected 1 DNS SAN, got %d", got)
	}
	if got := len(leaf.Certificate.IPAddresses); got != 2 {
		t.Errorf("expected 2 IP SANs, got %d", got)
	}
	if got := len(leaf.Certificate.EmailAddresses); got != 1 {
		t.Errorf("expected 1 email SAN, got %d", got)
	}

	if err := VerifyChain(leaf.Certificate,
		[]*x509.Certificate{inter.Certificate},
		[]*x509.Certificate{root.Certificate}); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}

	// The key generated with the CSR must match the issued certificate.
	if err := KeyMatchesCert(gen.PrivateKey, leaf.Certificate); err != nil {
		t.Fatalf("generated key does not match issued certificate: %v", err)
	}
}

func TestSignRejectsValidityBeyondCA(t *testing.T) {
	root, err := CreateCA(CAParams{
		Subject: Subject{CommonName: "Short Lived CA"},
		KeyType: KeyECP256,
		Days:    30,
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	gen, _ := GenerateCSR(CSRRequest{Subject: Subject{CommonName: "x.example.test"}, KeyType: KeyECP256})
	csr, _ := ParseCSR(gen.CSRPEM)
	_, err = Sign(SignParams{CSR: csr, Issuer: root.Certificate, IssuerKey: root.PrivateKey, Days: 365})
	if err == nil {
		t.Fatal("expected an error when the leaf outlives the CA")
	}
	if !strings.Contains(err.Error(), "CA expires") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestServerProfilePromotesCNToSAN(t *testing.T) {
	root, _ := CreateCA(CAParams{Subject: Subject{CommonName: "Root"}, KeyType: KeyECP256, Days: 365})
	gen, _ := GenerateCSR(CSRRequest{Subject: Subject{CommonName: "www.example.test"}, KeyType: KeyECP256})
	csr, _ := ParseCSR(gen.CSRPEM)
	res, err := Sign(SignParams{CSR: csr, Issuer: root.Certificate, IssuerKey: root.PrivateKey,
		Profile: ProfileServer, Days: 30})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(res.Certificate.DNSNames) != 1 || res.Certificate.DNSNames[0] != "www.example.test" {
		t.Errorf("CN was not promoted to a DNS SAN: %v", res.Certificate.DNSNames)
	}
}

func TestCRLRoundTrip(t *testing.T) {
	root, _ := CreateCA(CAParams{Subject: Subject{CommonName: "CRL Root"}, KeyType: KeyECP256, Days: 365})
	der, pemBytes, err := CreateCRL(CRLParams{
		Issuer:    root.Certificate,
		IssuerKey: root.PrivateKey,
		Number:    1,
		ValidDays: 7,
		Revoked: []RevokedEntry{
			{SerialHex: "0A1B2C3D", RevokedAt: time.Now().Add(-time.Hour), Reason: ReasonKeyCompromise},
		},
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	if !strings.Contains(string(pemBytes), "X509 CRL") {
		t.Error("PEM output is not a CRL block")
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("expected 1 revoked entry, got %d", len(crl.RevokedCertificateEntries))
	}
	if err := crl.CheckSignatureFrom(root.Certificate); err != nil {
		t.Errorf("CRL signature does not verify against the CA: %v", err)
	}
}

func TestParsePrivateKeyPEMFormats(t *testing.T) {
	for _, kt := range []KeyType{KeyRSA2048, KeyECP256, KeyEd25519} {
		key, err := GenerateKey(kt)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", kt, err)
		}
		pemBytes, err := EncodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM(%s): %v", kt, err)
		}
		back, err := ParsePrivateKeyPEM(pemBytes)
		if err != nil {
			t.Fatalf("ParsePrivateKeyPEM(%s): %v", kt, err)
		}
		if KeyTypeOf(back) != kt {
			t.Errorf("round trip changed key type: %s -> %s", kt, KeyTypeOf(back))
		}
	}
}

func TestParseKeyTypeAliases(t *testing.T) {
	cases := map[string]KeyType{
		"RSA 4096":   KeyRSA4096,
		"p-256":      KeyECP256,
		"prime256v1": KeyECP256,
		"ed25519":    KeyEd25519,
		"":           KeyRSA2048,
		"secp384r1":  KeyECP384,
	}
	for in, want := range cases {
		got, err := ParseKeyType(in)
		if err != nil {
			t.Errorf("ParseKeyType(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseKeyType(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := ParseKeyType("dsa-1024"); err == nil {
		t.Error("expected an error for an unsupported key type")
	}
}
