// Package gocaclient is a typed client for a goca server's REST API. It is
// what `gocactl` uses instead of opening the database, and it is deliberately
// the only thing in the client binary that knows about HTTP.
//
// It does not import internal/store, and must not start: that package links
// both SQL drivers (measured: 244 packages, including modernc.org/sqlite and
// pgx), which would put a 25 MB database engine inside a client that never
// opens a database. The DTOs in types.go mirror the server's JSON instead,
// with drift_test.go pinning them to the real server types so the copies
// cannot quietly diverge.
package gocaclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// Options configure a Client.
type Options struct {
	// Server is the goca base URL, e.g. https://ca.example.com.
	Server string
	// Token is an API token, as minted by Login or `goca token create`.
	Token string
	// CACertFile trusts a specific CA when the server's certificate is not
	// signed by one already in the system pool - the common case for a goca
	// serving TLS from its own PKI.
	CACertFile string
	// InsecureSkipVerify disables certificate verification entirely.
	InsecureSkipVerify bool
	Timeout            time.Duration
	// UserAgent identifies the client; leave empty for the default.
	UserAgent string
}

// Client talks to one goca server.
type Client struct {
	server string
	token  string
	ua     string
	http   *http.Client
}

// Version is stamped by the binary that links this package, so the server can
// see which client version is calling.
var Version = "dev"

// New builds a client. It performs no I/O, so a bad server URL surfaces here
// rather than on the first request.
func New(opts Options) (*Client, error) {
	server := strings.TrimRight(strings.TrimSpace(opts.Server), "/")
	if server == "" {
		return nil, errors.New("no goca server configured: pass --server, set GOCACTL_SERVER, or run `gocactl login`")
	}
	if !strings.Contains(server, "://") {
		// A bare host is almost certainly meant to be https; guessing http
		// would silently send the token in the clear.
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL %q: %w", opts.Server, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q: no host", opts.Server)
	}

	tlsCfg := &tls.Config{}
	if opts.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // opt-in, and warned about at the call site
	}
	if opts.CACertFile != "" {
		pem, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read --ca-cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s contains no certificates", opts.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = fmt.Sprintf("gocactl/%s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
	}
	return &Client{
		server: server,
		token:  opts.Token,
		ua:     ua,
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Server returns the base URL this client talks to.
func (c *Client) Server() string { return c.server }

// Result carries a decoded value alongside the exact bytes the server sent.
//
// `gocactl --json` prints Raw rather than re-marshalling Value, so its output
// is a faithful view of the API: a field the DTOs have not caught up with
// still reaches the user instead of being silently dropped on the way through.
type Result[T any] struct {
	Value T
	Raw   json.RawMessage
}

// do performs a request and decodes a JSON response into out (which may be
// nil). It returns the raw body either way.
func (c *Client) do(ctx context.Context, method, path string, body, out any) (json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.server+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, c.server+path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return raw, parseAPIError(resp, raw)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, fmt.Errorf("decode %s %s response: %w", method, path, err)
		}
	}
	return raw, nil
}

// get is do with no request body.
func (c *Client) get(ctx context.Context, path string, out any) (json.RawMessage, error) {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// Download fetches one of the raw-bytes endpoints (the .../download/{file}
// routes), which return a file rather than JSON. extra carries headers such as
// X-Bundle-Password, which must not travel in the query string. It returns the
// server's suggested file name alongside the bytes.
func (c *Client) Download(ctx context.Context, path string, extra map[string]string) (name string, data []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+path, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("GET %s: %w", c.server+path, err)
	}
	defer resp.Body.Close()

	data, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", nil, parseAPIError(resp, data)
	}
	return filenameFromDisposition(resp.Header.Get("Content-Disposition")), data, nil
}

// filenameFromDisposition pulls the file name out of a Content-Disposition
// header, so a download lands under the name the server chose.
func filenameFromDisposition(v string) string {
	_, params, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}
	return params["filename"]
}
