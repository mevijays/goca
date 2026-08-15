package web

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/mevijays/goca/internal/pki"
)

// The SSL utility is goca's `openssl x509/req/pkey -text -noout` equivalent:
// paste or upload a certificate, private key or CSR and see it decoded. It
// deliberately works without an account (see server.go's route registration
// and optionalUser) - there's nothing here to protect, since nothing it
// receives is ever stored, logged, or written to the database. A private
// key's own material is never echoed back either, only its type and a
// fingerprint of its *public* half, which is also how a pasted cert+key pair
// gets cross-checked for a match.
//
// CSRF is deliberately not enforced on the POST handler: the double-submit
// cookie a browser session would carry protects against a state change being
// forged in an authenticated user's name, and this endpoint makes none - the
// response is only ever the parse of whatever the requester themselves sent,
// scriptable with a bare curl POST the same way the CSR/CA endpoints are not.

// sslBlock is one PEM block found in the SSL utility's input, decoded or, on
// failure, carrying why.
type sslBlock struct {
	Label string // "Certificate #1", "Private key", ...
	Kind  string // certificate | csr | key | unsupported
	PEM   string // this block's own PEM text, for the copy button
	Error string // set instead of the fields below when parsing failed

	Cert *pki.CertInfo
	CSR  *pki.CSRInfo
	Key  *sslKeyInfo
}

// sslKeyInfo summarises a private key without ever including its material.
type sslKeyInfo struct {
	KeyType         string
	SPKIFingerprint string   // SHA-256 of the DER-encoded public key
	Matches         []string // labels of other blocks in this input sharing this public key
}

// sslInspectResult is what handleSSLToolSubmit hands to the template.
type sslInspectResult struct {
	Blocks []*sslBlock
	Error  string // set when no PEM data was found at all

	// EchoInput is what the form's textarea redisplays after a submit: the
	// input with every private key block replaced by a placeholder line, so
	// re-showing what was pasted (handy for fixing a typo, or pasting a
	// second block to check against the first) never puts key material back
	// on the page.
	EchoInput string
}

// inspectSSLInput parses every PEM block in raw and describes it. A block
// that fails to parse is reported individually rather than aborting the
// whole request, so one bad paste doesn't hide results for the rest.
func inspectSSLInput(raw []byte) sslInspectResult {
	var blocks []*sslBlock
	fingerprints := map[int]string{} // block index -> SPKI fingerprint, for cross-matching

	rest := raw
	certN, csrN := 0, 0
	sawKey := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blockPEM := string(pem.EncodeToMemory(block))

		switch block.Type {
		case "CERTIFICATE":
			certN++
			b := &sslBlock{Label: fmt.Sprintf("Certificate #%d", certN), Kind: "certificate", PEM: blockPEM}
			if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
				b.Error = err.Error()
			} else {
				info := pki.Describe(cert)
				b.Cert = &info
				if fp, err := spkiFingerprint(cert.PublicKey); err == nil {
					fingerprints[len(blocks)] = fp
				}
			}
			blocks = append(blocks, b)

		case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
			csrN++
			label := "Certificate signing request"
			if csrN > 1 {
				label = fmt.Sprintf("Certificate signing request #%d", csrN)
			}
			b := &sslBlock{Label: label, Kind: "csr", PEM: blockPEM}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			switch {
			case err != nil:
				b.Error = err.Error()
			case csr.CheckSignature() != nil:
				b.Error = "signature does not verify: " + csr.CheckSignature().Error()
			default:
				info := pki.DescribeCSR(csr)
				b.CSR = &info
				if fp, err := spkiFingerprint(csr.PublicKey); err == nil {
					fingerprints[len(blocks)] = fp
				}
			}
			blocks = append(blocks, b)

		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			label := "Private key"
			if sawKey {
				label = "Private key (additional)"
			}
			sawKey = true
			b := &sslBlock{Label: label, Kind: "key", PEM: blockPEM}
			if key, err := pki.ParsePrivateKeyPEM([]byte(blockPEM)); err != nil {
				b.Error = err.Error()
			} else if pub, err := pki.PublicKeyOf(key); err != nil {
				b.Error = err.Error()
			} else {
				b.Key = &sslKeyInfo{KeyType: string(pki.KeyTypeOf(key))}
				if fp, err := spkiFingerprint(pub); err == nil {
					b.Key.SPKIFingerprint = fp
					fingerprints[len(blocks)] = fp
				}
			}
			blocks = append(blocks, b)

		case "ENCRYPTED PRIVATE KEY":
			blocks = append(blocks, &sslBlock{
				Label: "Encrypted private key", Kind: "key", PEM: blockPEM,
				Error: "this key is password-protected; decrypt it first, e.g. " +
					"openssl pkcs8 -topk8 -nocrypt -in enc.key -out plain.key",
			})

		default:
			blocks = append(blocks, &sslBlock{
				Label: "Unrecognized PEM block", Kind: "unsupported", PEM: blockPEM,
				Error: fmt.Sprintf("goca does not recognize a %q block", block.Type),
			})
		}
	}

	if len(blocks) == 0 {
		// Nothing decoded as PEM at all, so there is no key material to
		// protect - safe to show back exactly what was submitted.
		return sslInspectResult{
			Error: "No PEM data found. Paste (or upload) a certificate, private key, " +
				`or CSR beginning with "-----BEGIN ...-----".`,
			EchoInput: string(raw),
		}
	}

	// Cross-reference public keys: a key block lists which other blocks in
	// the same paste share its public key, so a cert+key pair pasted
	// together shows whether they actually match.
	for i, b := range blocks {
		if b.Key == nil || fingerprints[i] == "" {
			continue
		}
		for j, other := range blocks {
			if i == j || fingerprints[j] != fingerprints[i] {
				continue
			}
			b.Key.Matches = append(b.Key.Matches, other.Label)
		}
	}

	return sslInspectResult{Blocks: blocks, EchoInput: echoInput(blocks)}
}

// echoInput rebuilds text safe to redisplay in the form: every block's own
// PEM, except private keys, which are replaced by a placeholder - see
// sslInspectResult.EchoInput.
func echoInput(blocks []*sslBlock) string {
	var b strings.Builder
	for i, block := range blocks {
		if i > 0 {
			b.WriteByte('\n')
		}
		if block.Kind == "key" {
			fmt.Fprintf(&b, "# %s decoded below - not redisplayed here\n", block.Label)
			continue
		}
		b.WriteString(block.PEM)
	}
	return strings.TrimRight(b.String(), "\n")
}

// spkiFingerprint hashes a public key's DER-encoded SubjectPublicKeyInfo, the
// same representation regardless of whether it came from a certificate, a
// CSR or a private key - which is what makes it useful for matching a key
// against the certificate or CSR it belongs to.
func spkiFingerprint(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return pki.FingerprintSHA256(der), nil
}

func (s *Server) handleSSLToolForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "ssl_tool.html", viewData{
		Title: "SSL utility",
		Nav:   "ssl",
		Data:  map[string]any{},
	})
}

func (s *Server) handleSSLToolSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // 2 MB is generous for a cert/key/CSR paste
	// The web form always submits multipart (it has a file input), but a
	// plain "curl -d" or www-form-urlencoded POST - paste-only, no file - is
	// a reasonable way to script this endpoint too, so accept either. Picking
	// the parser from the Content-Type up front, rather than trying
	// ParseMultipartForm and falling back to ParseForm on error, matters:
	// ParseMultipartForm calls ParseForm internally first, which would
	// consume (and partially populate r.PostForm from) the same
	// MaxBytesReader-limited body, so a naive fallback's second ParseForm
	// call sees r.PostForm already set and silently no-ops instead of
	// surfacing the "body too large" error.
	var err error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		err = r.ParseMultipartForm(2 << 20)
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		s.render(w, r, "ssl_tool.html", viewData{
			Title: "SSL utility",
			Nav:   "ssl",
			Data: map[string]any{
				"Result": sslInspectResult{
					Error: "Could not read the submitted form (2 MB max): " + err.Error(),
				},
			},
		})
		return
	}

	input := uploadedFile(r, "input_file")
	if input == "" {
		input = r.FormValue("input_text")
	}
	result := inspectSSLInput([]byte(input))

	s.render(w, r, "ssl_tool.html", viewData{
		Title: "SSL utility",
		Nav:   "ssl",
		// The textarea redisplays result.EchoInput, not the raw input - see
		// its doc comment. This is the one place that matters: it's what
		// keeps a submitted private key off the page on the response too,
		// not just out of the decoded summary below it.
		Data: map[string]any{
			"Input":  result.EchoInput,
			"Result": result,
		},
	})
}
