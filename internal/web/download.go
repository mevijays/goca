package web

import (
	"archive/zip"
	"bytes"
	"encoding/pem"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// zipEntry is one file inside a generated archive.
type zipEntry struct {
	Name string
	Data []byte
}

func writeZip(w http.ResponseWriter, filename string, entries []zipEntry) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		if len(e.Data) == 0 {
			continue
		}
		f, err := zw.Create(e.Name)
		if err != nil {
			http.Error(w, "zip error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := f.Write(e.Data); err != nil {
			http.Error(w, "zip error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := zw.Close(); err != nil {
		http.Error(w, "zip error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sendFile(w, filename, "application/zip", buf.Bytes())
}

func sendFile(w http.ResponseWriter, filename, contentType string, data []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// safeFileName turns a common name into something safe for a download.
func safeFileName(s string) string {
	s = unsafeFileChars.ReplaceAllString(strings.TrimSpace(s), "_")
	s = strings.Trim(s, "._-")
	if s == "" {
		s = "certificate"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// derFromPEM extracts the DER bytes of the first PEM block.
func derFromPEM(pemStr string) []byte {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil
	}
	return block.Bytes
}

//
// ---------- CA downloads ----------
//

// serveCADownload writes one CA artefact. It is shared by the portal and API.
// Returns false when the requested file name is unknown.
func (s *Server) serveCADownload(w http.ResponseWriter, r *http.Request, c *store.CA, file string, isAdmin bool) bool {
	base := c.Slug
	switch file {
	case "ca.crt", "ca.pem", "cert.pem", "certificate.pem":
		sendFile(w, base+".crt", "application/x-pem-file", []byte(c.CertPEM))
	case "ca.der", "cert.der":
		sendFile(w, base+".der", "application/pkix-cert", derFromPEM(c.CertPEM))
	case "chain.pem", "ca-chain.pem":
		chain, err := s.svc.CAChainPEM(r.Context(), c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		sendFile(w, base+"-chain.pem", "application/x-pem-file", chain)
	case "ca.key", "key.pem":
		if !isAdmin {
			s.renderError(w, r, http.StatusForbidden, "Administrator access required",
				"Only administrators may download a CA private key.")
			return true
		}
		key, err := s.svc.CAKeyPEM(r.Context(), c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		s.svc.AuditWithIP(r.Context(), actorName(r), "ca.key_download", c.Name, "", clientIP(r))
		sendFile(w, base+".key", "application/x-pem-file", key)
	case "crl.pem", "crl.crl", "crl.der":
		der, pemBytes, err := s.svc.GenerateCRL(r.Context(), c.ID, actorName(r))
		if err != nil {
			http.Error(w, "CRL generation failed: "+err.Error(), http.StatusInternalServerError)
			return true
		}
		if file == "crl.pem" {
			sendFile(w, base+".crl.pem", "application/x-pem-file", pemBytes)
		} else {
			sendFile(w, base+".crl", "application/pkix-crl", der)
		}
	case "request.csr", "csr.pem":
		if c.CSRPEM == "" {
			s.renderError(w, r, http.StatusNotFound, "No signing request stored",
				"This authority was not created from a request goca generated.")
			return true
		}
		sendFile(w, base+".csr", "application/pkcs10", []byte(c.CSRPEM))
	case "bundle.zip":
		chain, _ := s.svc.CAChainPEM(r.Context(), c)
		_, crlPEM, _ := s.svc.GenerateCRL(r.Context(), c.ID, actorName(r))
		entries := []zipEntry{
			{Name: base + ".crt", Data: []byte(c.CertPEM)},
			{Name: base + "-chain.pem", Data: chain},
			{Name: base + ".crl.pem", Data: crlPEM},
			{Name: "README.txt", Data: []byte(caReadme(c, s.cfg.Server.BaseURL))},
		}
		if isAdmin {
			if key, err := s.svc.CAKeyPEM(r.Context(), c); err == nil {
				entries = append(entries, zipEntry{Name: base + ".key", Data: key})
			}
			s.svc.AuditWithIP(r.Context(), actorName(r), "ca.key_download", c.Name, "in bundle.zip", clientIP(r))
		}
		writeZip(w, base+"-bundle.zip", entries)
	default:
		return false
	}
	return true
}

func caReadme(c *store.CA, baseURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n\n", c.Name, strings.Repeat("=", len(c.Name)))
	fmt.Fprintf(&b, "Subject      : %s\n", c.Subject)
	fmt.Fprintf(&b, "Serial       : %s\n", c.SerialHex)
	fmt.Fprintf(&b, "Key type     : %s\n", c.KeyType)
	fmt.Fprintf(&b, "Valid        : %s to %s\n",
		c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(&b, "SHA-256      : %s\n\n", c.Fingerprint)
	fmt.Fprintf(&b, "Files\n-----\n")
	fmt.Fprintf(&b, "  %s.crt        CA certificate (PEM)\n", c.Slug)
	fmt.Fprintf(&b, "  %s-chain.pem  CA certificate plus its issuers\n", c.Slug)
	fmt.Fprintf(&b, "  %s.crl.pem    Current certificate revocation list\n", c.Slug)
	fmt.Fprintf(&b, "  %s.key        CA private key (present only for administrators)\n\n", c.Slug)
	if baseURL != "" {
		fmt.Fprintf(&b, "Live distribution URLs\n----------------------\n")
		fmt.Fprintf(&b, "  %s/public/ca/%s.crt\n", baseURL, c.Slug)
		fmt.Fprintf(&b, "  %s/public/crl/%s.crl\n\n", baseURL, c.Slug)
	}
	fmt.Fprintf(&b, "Trusting this CA on Linux\n-------------------------\n")
	fmt.Fprintf(&b, "  sudo cp %s.crt /usr/local/share/ca-certificates/\n", c.Slug)
	fmt.Fprintf(&b, "  sudo update-ca-certificates\n")
	return b.String()
}

//
// ---------- certificate downloads ----------
//

// serveCertDownload writes one certificate artefact. Returns false for an
// unknown file name.
func (s *Server) serveCertDownload(w http.ResponseWriter, r *http.Request, c *store.Certificate, file string) bool {
	base := safeFileName(c.CommonName)
	switch file {
	case "cert.pem", "cert.crt", "certificate.pem":
		ext := ".pem"
		if file == "cert.crt" {
			ext = ".crt"
		}
		sendFile(w, base+ext, "application/x-pem-file", []byte(c.CertPEM))
	case "cert.der":
		sendFile(w, base+".der", "application/pkix-cert", derFromPEM(c.CertPEM))
	case "key.pem", "key":
		key, err := s.svc.CertKeyPEM(r.Context(), c)
		if err != nil {
			s.renderError(w, r, http.StatusNotFound, "No stored private key", err.Error())
			return true
		}
		s.svc.AuditWithIP(r.Context(), actorName(r), "cert.key_download", c.CommonName,
			"serial="+c.SerialHex, clientIP(r))
		sendFile(w, base+".key", "application/x-pem-file", key)
	case "chain.pem":
		caRec, err := s.svc.GetCA(r.Context(), c.CAID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		chain, err := s.svc.CAChainPEM(r.Context(), caRec)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		sendFile(w, base+"-chain.pem", "application/x-pem-file", chain)
	case "fullchain.pem":
		full, err := s.svc.CertChainPEM(r.Context(), c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		sendFile(w, base+"-fullchain.pem", "application/x-pem-file", full)
	case "request.csr", "csr.pem":
		if c.CSRPEM == "" {
			s.renderError(w, r, http.StatusNotFound, "No CSR stored",
				"This certificate has no stored signing request.")
			return true
		}
		sendFile(w, base+".csr", "application/pkcs10", []byte(c.CSRPEM))
	case "bundle.p12", "bundle.pfx":
		password := r.URL.Query().Get("password")
		p12, err := s.svc.CertBundleP12(r.Context(), c, password)
		if err != nil {
			s.renderError(w, r, http.StatusBadRequest, "Cannot build PKCS#12 bundle", err.Error())
			return true
		}
		s.svc.AuditWithIP(r.Context(), actorName(r), "cert.key_download", c.CommonName,
			"pkcs12 serial="+c.SerialHex, clientIP(r))
		sendFile(w, base+".p12", "application/x-pkcs12", p12)
	case "bundle.zip":
		full, _ := s.svc.CertChainPEM(r.Context(), c)
		caRec, _ := s.svc.GetCA(r.Context(), c.CAID)
		var chain []byte
		if caRec != nil {
			chain, _ = s.svc.CAChainPEM(r.Context(), caRec)
		}
		entries := []zipEntry{
			{Name: base + ".crt", Data: []byte(c.CertPEM)},
			{Name: base + "-chain.pem", Data: chain},
			{Name: base + "-fullchain.pem", Data: full},
		}
		if c.CSRPEM != "" {
			entries = append(entries, zipEntry{Name: base + ".csr", Data: []byte(c.CSRPEM)})
		}
		if key, err := s.svc.CertKeyPEM(r.Context(), c); err == nil {
			entries = append(entries, zipEntry{Name: base + ".key", Data: key})
			s.svc.AuditWithIP(r.Context(), actorName(r), "cert.key_download", c.CommonName,
				"in bundle.zip serial="+c.SerialHex, clientIP(r))
		}
		entries = append(entries, zipEntry{Name: "README.txt", Data: []byte(certReadme(c))})
		writeZip(w, base+"-bundle.zip", entries)
	default:
		return false
	}
	return true
}

func certReadme(c *store.Certificate) string {
	base := safeFileName(c.CommonName)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n\n", c.CommonName, strings.Repeat("=", len(c.CommonName)))
	fmt.Fprintf(&b, "Subject     : %s\n", c.Subject)
	fmt.Fprintf(&b, "SANs        : %s\n", c.SANsDisplay())
	fmt.Fprintf(&b, "Serial      : %s\n", c.SerialHex)
	fmt.Fprintf(&b, "Issuer      : %s\n", c.CAName)
	fmt.Fprintf(&b, "Profile     : %s\n", c.Profile)
	fmt.Fprintf(&b, "Key type    : %s\n", c.KeyType)
	fmt.Fprintf(&b, "Valid       : %s to %s\n",
		c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(&b, "SHA-256     : %s\n\n", c.Fingerprint)
	fmt.Fprintf(&b, "Files\n-----\n")
	fmt.Fprintf(&b, "  %s.crt            leaf certificate\n", base)
	fmt.Fprintf(&b, "  %s.key            private key (only if goca stored it)\n", base)
	fmt.Fprintf(&b, "  %s-chain.pem      issuing CA chain\n", base)
	fmt.Fprintf(&b, "  %s-fullchain.pem  leaf + chain, for nginx/haproxy\n\n", base)
	fmt.Fprintf(&b, "nginx\n-----\n")
	fmt.Fprintf(&b, "  ssl_certificate     %s-fullchain.pem;\n", base)
	fmt.Fprintf(&b, "  ssl_certificate_key %s.key;\n\n", base)
	fmt.Fprintf(&b, "Verify\n------\n")
	fmt.Fprintf(&b, "  openssl verify -CAfile %s-chain.pem %s.crt\n", base, base)
	return b.String()
}

//
// ---------- portal download entry points ----------
//

func (s *Server) handleCADownload(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCA(w, r)
	if !ok {
		return
	}
	file := r.PathValue("file")
	if !s.serveCADownload(w, r, c, file, currentUser(r).IsAdmin()) {
		s.renderError(w, r, http.StatusNotFound, "Unknown file",
			fmt.Sprintf("%q is not something this authority can produce.", file))
	}
}

func (s *Server) handleCertDownload(w http.ResponseWriter, r *http.Request) {
	c, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	file := r.PathValue("file")
	if !s.serveCertDownload(w, r, c, file) {
		s.renderError(w, r, http.StatusNotFound, "Unknown file",
			fmt.Sprintf("%q is not something this certificate can produce.", file))
	}
}

//
// ---------- anonymous distribution endpoints ----------
//

// publicSlug splits "acme-root-ca.crt" into its slug and extension.
func publicSlug(file string) (slug, ext string) {
	if i := strings.LastIndex(file, "."); i > 0 {
		return file[:i], strings.ToLower(file[i+1:])
	}
	return file, ""
}

func (s *Server) handlePublicCACert(w http.ResponseWriter, r *http.Request) {
	slug, ext := publicSlug(r.PathValue("file"))
	c, err := s.svc.Store().GetCABySlug(r.Context(), slug)
	if err != nil {
		http.Error(w, "no such certificate authority", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	if ext == "der" || ext == "cer" {
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", c.Slug+".der"))
		_, _ = w.Write(derFromPEM(c.CertPEM))
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", c.Slug+".crt"))
	_, _ = w.Write([]byte(c.CertPEM))
}

func (s *Server) handlePublicCRL(w http.ResponseWriter, r *http.Request) {
	slug, ext := publicSlug(r.PathValue("file"))
	c, err := s.svc.Store().GetCABySlug(r.Context(), slug)
	if err != nil {
		http.Error(w, "no such certificate authority", http.StatusNotFound)
		return
	}
	der, pemBytes, err := s.svc.GenerateCRL(r.Context(), c.ID, "public")
	if err != nil {
		http.Error(w, "CRL generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	// .crl is the DER form every OS expects; .pem is offered for convenience.
	if ext == "pem" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", c.Slug+".crl.pem"))
		_, _ = w.Write(pemBytes)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", c.Slug+".crl"))
	_, _ = w.Write(der)
}

// actorName returns the acting username for audit records.
func actorName(r *http.Request) string {
	if u := currentUser(r); u != nil {
		return u.Username
	}
	return "anonymous"
}

// describeOrNil is a small helper used by the API layer.
func describeOrNil(pemStr string) *pki.CertInfo {
	cert, err := pki.ParseCertPEM([]byte(pemStr))
	if err != nil {
		return nil
	}
	info := pki.Describe(cert)
	return &info
}
