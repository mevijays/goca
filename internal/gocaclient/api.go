package gocaclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The typed API surface. Every method returns a Result carrying both the
// decoded value and the server's raw bytes, so `--json` can print the latter
// untouched - see Result's doc comment.
//
// References (a CA slug, a secret name, a username) are passed straight
// through to the server, which resolves them itself; the client does not
// pre-resolve, which would cost a round trip and race with concurrent changes.

// ref escapes a path segment. Secret names are path-like ("team-a/db/password")
// so their slashes must be encoded or the router would see extra segments.
func ref(v string) string { return url.PathEscape(v) }

//
// ---------- authentication ----------
//

// Login exchanges a password for an API token. It is the one call that works
// without a token already configured.
func (c *Client) Login(ctx context.Context, in LoginInput) (Result[*LoginResult], error) {
	var out LoginResult
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/auth/login", in, &out)
	return Result[*LoginResult]{Value: &out, Raw: raw}, err
}

// Me describes the caller and the credential they used.
func (c *Client) Me(ctx context.Context) (Result[*Me], error) {
	var out Me
	raw, err := c.get(ctx, "/api/v1/me", &out)
	return Result[*Me]{Value: &out, Raw: raw}, err
}

// Health is the unauthenticated probe, and doubles as a reachability check.
func (c *Client) Health(ctx context.Context) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.get(ctx, "/api/v1/health", &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

// Stats summarises the server for a dashboard-style view.
func (c *Client) Stats(ctx context.Context) (Result[*Stats], error) {
	var out Stats
	raw, err := c.get(ctx, "/api/v1/stats", &out)
	return Result[*Stats]{Value: &out, Raw: raw}, err
}

//
// ---------- certificate authorities ----------
//

func (c *Client) ListCAs(ctx context.Context) (Result[[]CA], error) {
	var env caListEnvelope
	raw, err := c.get(ctx, "/api/v1/cas", &env)
	return Result[[]CA]{Value: env.CAs, Raw: raw}, err
}

func (c *Client) GetCA(ctx context.Context, caRef string) (Result[*CA], error) {
	var out CA
	raw, err := c.get(ctx, "/api/v1/cas/"+ref(caRef), &out)
	return Result[*CA]{Value: &out, Raw: raw}, err
}

func (c *Client) CreateCA(ctx context.Context, in CreateCAInput) (Result[*CA], error) {
	var out CA
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/cas", in, &out)
	return Result[*CA]{Value: &out, Raw: raw}, err
}

func (c *Client) DeleteCA(ctx context.Context, caRef string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/v1/cas/"+ref(caRef), nil, nil)
	return err
}

func (c *Client) SetDefaultCA(ctx context.Context, caRef string) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/cas/"+ref(caRef)+"/default", nil, nil)
	return err
}

func (c *Client) SetCAStatus(ctx context.Context, caRef, status string) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/cas/"+ref(caRef)+"/status",
		map[string]string{"status": status}, nil)
	return err
}

// GenerateCRL signs a fresh CRL and returns it as PEM.
func (c *Client) GenerateCRL(ctx context.Context, caRef string) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/cas/"+ref(caRef)+"/crl", nil, &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

func (c *Client) SubordinateCSR(ctx context.Context, in SubordinateCSRInput) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/cas/request", in, &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

func (c *Client) ImportCA(ctx context.Context, in ImportCAInput) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/cas/import", in, &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

func (c *Client) ImportSignedCA(ctx context.Context, caRef string, in CompleteSubordinateInput) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/cas/"+ref(caRef)+"/import-signed", in, &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

func (c *Client) PendingCAs(ctx context.Context) (Result[[]PendingCA], error) {
	var env pendingCAEnvelope
	raw, err := c.get(ctx, "/api/v1/cas/pending", &env)
	return Result[[]PendingCA]{Value: env.Pending, Raw: raw}, err
}

// CACSR returns the stored signing request of a pending authority.
func (c *Client) CACSR(ctx context.Context, caRef string) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.get(ctx, "/api/v1/cas/"+ref(caRef)+"/csr", &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

func (c *Client) RevokeCA(ctx context.Context, caRef string, reason int, cascade bool) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/cas/"+ref(caRef)+"/revoke",
		map[string]any{"reason": reason, "cascade": cascade}, &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

// DownloadCA fetches one CA artefact: ca.crt, ca.pem, ca.der, ca.key,
// chain.pem, crl.pem, crl.crl, request.csr or bundle.zip.
func (c *Client) DownloadCA(ctx context.Context, caRef, file string) (string, []byte, error) {
	return c.Download(ctx, "/api/v1/cas/"+ref(caRef)+"/download/"+ref(file), nil)
}

//
// ---------- certificates ----------
//

func (c *Client) ListCerts(ctx context.Context, f CertFilter) (Result[*CertPage], error) {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("q", f.Query)
	set("ca", f.CARef)
	set("status", f.Status)
	set("profile", f.Profile)
	set("requested_by", f.RequestedBy)
	set("sort", f.SortBy)
	if f.ExpiringIn > 0 {
		q.Set("expiring", strconv.Itoa(f.ExpiringIn))
	}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	if f.Offset > 0 {
		q.Set("offset", strconv.Itoa(f.Offset))
	}
	if f.SortDesc {
		q.Set("order", "desc")
	}

	path := "/api/v1/certificates"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out CertPage
	raw, err := c.get(ctx, path, &out)
	return Result[*CertPage]{Value: &out, Raw: raw}, err
}

// GetCert accepts a numeric id or a hex serial.
func (c *Client) GetCert(ctx context.Context, certRef string) (Result[*Certificate], error) {
	var out Certificate
	raw, err := c.get(ctx, "/api/v1/certificates/"+ref(certRef), &out)
	return Result[*Certificate]{Value: &out, Raw: raw}, err
}

func (c *Client) IssueCert(ctx context.Context, in IssueInput) (Result[*IssueResult], error) {
	var out IssueResult
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/certificates", in, &out)
	return Result[*IssueResult]{Value: &out, Raw: raw}, err
}

func (c *Client) RevokeCert(ctx context.Context, certRef string, reason int) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/certificates/"+ref(certRef)+"/revoke",
		map[string]any{"reason": reason}, nil)
	return err
}

func (c *Client) DeleteCert(ctx context.Context, certRef string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/v1/certificates/"+ref(certRef), nil, nil)
	return err
}

func (c *Client) RenewCert(ctx context.Context, certRef string, in RenewInput) (Result[*IssueResult], error) {
	var out IssueResult
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/certificates/"+ref(certRef)+"/renew", in, &out)
	return Result[*IssueResult]{Value: &out, Raw: raw}, err
}

func (c *Client) CertHistory(ctx context.Context, certRef string) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.get(ctx, "/api/v1/certificates/"+ref(certRef)+"/history", &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

func (c *Client) HoldCert(ctx context.Context, certRef string) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/certificates/"+ref(certRef)+"/hold", nil, nil)
	return err
}

func (c *Client) ReleaseCert(ctx context.Context, certRef string) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/certificates/"+ref(certRef)+"/release", nil, nil)
	return err
}

func (c *Client) RenewExpiring(ctx context.Context, withinDays int) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/certificates/renew-expiring",
		map[string]any{"within_days": withinDays}, &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

func (c *Client) BulkRevoke(ctx context.Context, body map[string]any) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/certificates/bulk-revoke", body, &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

// DownloadCert fetches one certificate artefact: cert.pem, cert.crt, cert.der,
// key.pem, chain.pem, fullchain.pem, request.csr, bundle.p12 or bundle.zip.
// The PKCS#12 password travels in a header, never the query string.
func (c *Client) DownloadCert(ctx context.Context, certRef, file, p12Password string) (string, []byte, error) {
	var extra map[string]string
	if p12Password != "" {
		extra = map[string]string{"X-Bundle-Password": p12Password}
	}
	return c.Download(ctx, "/api/v1/certificates/"+ref(certRef)+"/download/"+ref(file), extra)
}

//
// ---------- tokens, users, audit ----------
//

func (c *Client) ListTokens(ctx context.Context) (Result[[]APIToken], error) {
	var env tokenListEnvelope
	raw, err := c.get(ctx, "/api/v1/tokens", &env)
	return Result[[]APIToken]{Value: env.Tokens, Raw: raw}, err
}

func (c *Client) CreateToken(ctx context.Context, name, role string, days int) (Result[map[string]any], error) {
	out := map[string]any{}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/tokens",
		map[string]any{"name": name, "role": role, "days": days}, &out)
	return Result[map[string]any]{Value: out, Raw: raw}, err
}

func (c *Client) RevokeToken(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/v1/tokens/"+strconv.FormatInt(id, 10), nil, nil)
	return err
}

func (c *Client) ListUsers(ctx context.Context) (Result[[]User], error) {
	var env userListEnvelope
	raw, err := c.get(ctx, "/api/v1/users", &env)
	return Result[[]User]{Value: env.Users, Raw: raw}, err
}

func (c *Client) CreateUser(ctx context.Context, username, password, role, displayName, email string) (Result[*User], error) {
	var out User
	body := map[string]any{"username": username, "password": password, "role": role}
	if displayName != "" {
		body["display_name"] = displayName
	}
	if email != "" {
		body["email"] = email
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/users", body, &out)
	return Result[*User]{Value: &out, Raw: raw}, err
}

// PatchUser updates role, disabled and/or password. Nil fields are left alone.
func (c *Client) PatchUser(ctx context.Context, userRef string, body map[string]any) (Result[*User], error) {
	var out User
	raw, err := c.do(ctx, http.MethodPatch, "/api/v1/users/"+ref(userRef), body, &out)
	return Result[*User]{Value: &out, Raw: raw}, err
}

func (c *Client) DeleteUser(ctx context.Context, userRef string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/v1/users/"+ref(userRef), nil, nil)
	return err
}

func (c *Client) ListAudit(ctx context.Context, limit int) (Result[[]AuditEntry], error) {
	path := "/api/v1/audit"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var env auditEnvelope
	raw, err := c.get(ctx, path, &env)
	return Result[[]AuditEntry]{Value: env.Entries, Raw: raw}, err
}

//
// ---------- secrets ----------
//

func (c *Client) ListSecrets(ctx context.Context, typ string) (Result[[]Secret], error) {
	path := "/api/v1/secrets"
	if typ != "" {
		path += "?type=" + url.QueryEscape(typ)
	}
	var env secretListEnvelope
	raw, err := c.get(ctx, path, &env)
	return Result[[]Secret]{Value: env.Secrets, Raw: raw}, err
}

func (c *Client) GetSecret(ctx context.Context, name string) (Result[*Secret], error) {
	var out Secret
	raw, err := c.get(ctx, "/api/v1/secrets/"+ref(name), &out)
	return Result[*Secret]{Value: &out, Raw: raw}, err
}

func (c *Client) CreateSecret(ctx context.Context, in CreateSecretInput) (Result[*Secret], error) {
	var out Secret
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/secrets", in, &out)
	return Result[*Secret]{Value: &out, Raw: raw}, err
}

func (c *Client) UpdateSecret(ctx context.Context, name string, body map[string]any) (Result[*Secret], error) {
	var out Secret
	raw, err := c.do(ctx, http.MethodPatch, "/api/v1/secrets/"+ref(name), body, &out)
	return Result[*Secret]{Value: &out, Raw: raw}, err
}

func (c *Client) DeleteSecret(ctx context.Context, name string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/v1/secrets/"+ref(name), nil, nil)
	return err
}

func (c *Client) SetSecretDisabled(ctx context.Context, name string, disabled bool) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/secrets/"+ref(name)+"/disable",
		map[string]any{"disabled": disabled}, nil)
	return err
}

// MaterializeSecret resolves a secret's current content into files, decoding
// the base64 the API uses to carry arbitrary bytes. version changes exactly
// when the content does.
func (c *Client) MaterializeSecret(ctx context.Context, name string) (files []SecretFile, version string, sec *Secret, err error) {
	var out struct {
		Secret  *Secret `json:"secret"`
		Version string  `json:"version"`
		Files   []struct {
			Name       string `json:"name"`
			DataBase64 string `json:"data_base64"`
		} `json:"files"`
	}
	if _, err := c.get(ctx, "/api/v1/secrets/"+ref(name)+"/materialize", &out); err != nil {
		return nil, "", nil, err
	}
	for _, f := range out.Files {
		data, err := base64.StdEncoding.DecodeString(f.DataBase64)
		if err != nil {
			return nil, "", nil, fmt.Errorf("secret %q file %q: invalid base64 from server: %w", name, f.Name, err)
		}
		files = append(files, SecretFile{Name: f.Name, Data: data})
	}
	return files, out.Version, out.Secret, nil
}

func (c *Client) SecretVersions(ctx context.Context, name string) (Result[[]SecretVersion], error) {
	var env secretVersionsEnvelope
	raw, err := c.get(ctx, "/api/v1/secrets/"+ref(name)+"/versions", &env)
	return Result[[]SecretVersion]{Value: env.Versions, Raw: raw}, err
}

func (c *Client) PutSecretVersion(ctx context.Context, name string, value []byte, contentType string) (Result[*SecretVersion], error) {
	var out SecretVersion
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/secrets/"+ref(name)+"/versions", map[string]any{
		"value_base64": base64.StdEncoding.EncodeToString(value),
		"content_type": contentType,
	}, &out)
	return Result[*SecretVersion]{Value: &out, Raw: raw}, err
}

// GetSecretVersion reads one specific version's plaintext.
func (c *Client) GetSecretVersion(ctx context.Context, name string, version int) ([]byte, error) {
	var out struct {
		ValueBase64 string `json:"value_base64"`
	}
	if _, err := c.get(ctx, fmt.Sprintf("/api/v1/secrets/%s/versions/%d", ref(name), version), &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.ValueBase64)
}

func (c *Client) DestroySecretVersion(ctx context.Context, name string, version int) error {
	_, err := c.do(ctx, http.MethodPost,
		fmt.Sprintf("/api/v1/secrets/%s/versions/%d/destroy", ref(name), version), nil, nil)
	return err
}

func (c *Client) SecretBindings(ctx context.Context, name string) (Result[[]SecretBinding], error) {
	var env secretBindingsEnvelope
	raw, err := c.get(ctx, "/api/v1/secrets/"+ref(name)+"/bindings", &env)
	return Result[[]SecretBinding]{Value: env.Bindings, Raw: raw}, err
}

func (c *Client) BindSecret(ctx context.Context, name, namespace, serviceAccount string, expiresInDays int) (Result[*SecretBinding], error) {
	var out SecretBinding
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/secrets/"+ref(name)+"/bindings", map[string]any{
		"k8s_namespace":       namespace,
		"k8s_service_account": serviceAccount,
		"expires_in_days":     expiresInDays,
	}, &out)
	return Result[*SecretBinding]{Value: &out, Raw: raw}, err
}

func (c *Client) UnbindSecret(ctx context.Context, bindingID int64) error {
	_, err := c.do(ctx, http.MethodDelete,
		"/api/v1/secret-bindings/"+strconv.FormatInt(bindingID, 10), nil, nil)
	return err
}

//
// ---------- ACME ----------
//

func (c *Client) ListEAB(ctx context.Context) (Result[[]EABCred], error) {
	var env eabListEnvelope
	raw, err := c.get(ctx, "/api/v1/acme/eab", &env)
	return Result[[]EABCred]{Value: env.Credentials, Raw: raw}, err
}

func (c *Client) CreateEAB(ctx context.Context, in CreateEABInput) (Result[*CreateEABResult], error) {
	var out CreateEABResult
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/acme/eab", in, &out)
	return Result[*CreateEABResult]{Value: &out, Raw: raw}, err
}

func (c *Client) GetEAB(ctx context.Context, id int64) (Result[*EABCred], error) {
	var out EABCred
	raw, err := c.get(ctx, "/api/v1/acme/eab/"+strconv.FormatInt(id, 10), &out)
	return Result[*EABCred]{Value: &out, Raw: raw}, err
}

func (c *Client) SetEABDisabled(ctx context.Context, id int64, disabled bool) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/acme/eab/"+strconv.FormatInt(id, 10)+"/disable",
		map[string]any{"disabled": disabled}, nil)
	return err
}

func (c *Client) DeleteEAB(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/v1/acme/eab/"+strconv.FormatInt(id, 10), nil, nil)
	return err
}

func (c *Client) ListACMEAccounts(ctx context.Context) (Result[[]AcmeAccount], error) {
	var env acmeAccountsEnvelope
	raw, err := c.get(ctx, "/api/v1/acme/accounts", &env)
	return Result[[]AcmeAccount]{Value: env.Accounts, Raw: raw}, err
}

func (c *Client) GetACMEAccount(ctx context.Context, id int64) (Result[*AcmeAccount], error) {
	var out AcmeAccount
	raw, err := c.get(ctx, "/api/v1/acme/accounts/"+strconv.FormatInt(id, 10), &out)
	return Result[*AcmeAccount]{Value: &out, Raw: raw}, err
}

func (c *Client) ACMEAccountOrders(ctx context.Context, id int64) (Result[[]AcmeOrder], error) {
	var env acmeOrdersEnvelope
	raw, err := c.get(ctx, "/api/v1/acme/accounts/"+strconv.FormatInt(id, 10)+"/orders", &env)
	return Result[[]AcmeOrder]{Value: env.Orders, Raw: raw}, err
}

// ACMEDirectoryURL is where an ACME client points its `server`. It is derived
// from the base URL rather than fetched, since the ACME directory endpoint sits
// outside /api/v1 and needs no credential.
func (c *Client) ACMEDirectoryURL() string {
	return strings.TrimRight(c.server, "/") + "/acme/directory"
}
