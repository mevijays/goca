// Package ldapauth authenticates portal users against an LDAP or Active
// Directory server and maps directory groups onto goca roles.
package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/mevijays/goca/internal/config"
)

// ErrInvalidCredentials is returned when the directory rejects the bind.
var ErrInvalidCredentials = errors.New("invalid username or password")

// ErrNotAllowed is returned when a user authenticates but is not a member of
// any group listed in allowed_groups.
var ErrNotAllowed = errors.New("account is not a member of any permitted group")

// Identity is what a successful directory lookup yields.
type Identity struct {
	Username    string   `json:"username"`
	DN          string   `json:"dn"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Groups      []string `json:"groups"`
	IsAdmin     bool     `json:"is_admin"`
}

// Client talks to a configured directory server.
type Client struct {
	cfg          config.LDAPConfig
	bindPassword string
}

// New builds a client. bindPassword is the already-decrypted service account
// password (empty for anonymous or DN-template binding).
func New(cfg config.LDAPConfig, bindPassword string) *Client {
	return &Client{cfg: cfg, bindPassword: bindPassword}
}

// Enabled reports whether LDAP is configured.
func (c *Client) Enabled() bool { return c != nil && c.cfg.Enabled && c.cfg.URL != "" }

func (c *Client) timeout() time.Duration {
	if c.cfg.Timeout > 0 {
		return c.cfg.Timeout
	}
	return 10 * time.Second
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	host := c.cfg.URL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	tc := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: c.cfg.InsecureSkipVerify, //nolint:gosec // operator opt-in for lab use
		MinVersion:         tls.VersionTLS12,
	}
	if c.cfg.CACertFile != "" {
		pem, err := os.ReadFile(c.cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read ldap ca_cert_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", c.cfg.CACertFile)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

// connect dials the directory and applies StartTLS when requested.
func (c *Client) connect(ctx context.Context) (*ldap.Conn, error) {
	if !c.Enabled() {
		return nil, errors.New("LDAP is not enabled in the configuration")
	}
	tc, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	conn, err := ldap.DialURL(c.cfg.URL, ldap.DialWithTLSConfig(tc),
		ldap.DialWithDialer(&net.Dialer{Timeout: c.timeout()}))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", c.cfg.URL, err)
	}
	conn.SetTimeout(c.timeout())
	if c.cfg.StartTLS {
		if err := conn.StartTLS(tc); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS to %s: %w", c.cfg.URL, err)
		}
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = deadline // ldap.Conn has no per-call deadline; SetTimeout covers it
	}
	return conn, nil
}

// bindService binds as the configured service account, if one is set.
func (c *Client) bindService(conn *ldap.Conn) error {
	if c.cfg.BindDN == "" {
		return nil // anonymous search
	}
	if err := conn.Bind(c.cfg.BindDN, c.bindPassword); err != nil {
		return fmt.Errorf("bind as service account %s: %w", c.cfg.BindDN, err)
	}
	return nil
}

// TestConnection verifies connectivity, the service bind and the search base.
func (c *Client) TestConnection(ctx context.Context) error {
	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := c.bindService(conn); err != nil {
		return err
	}
	if c.cfg.BaseDN == "" {
		return nil
	}
	req := ldap.NewSearchRequest(c.cfg.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, int(c.timeout().Seconds()), false, "(objectClass=*)", []string{"dn"}, nil)
	if _, err := conn.Search(req); err != nil {
		return fmt.Errorf("search base %s is not reachable: %w", c.cfg.BaseDN, err)
	}
	return nil
}

// Authenticate verifies a username and password and returns the directory
// identity, including group membership and the derived admin flag.
func (c *Client) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	id := &Identity{Username: username}

	// Resolve the user DN, either by template or by searching.
	if tmpl := strings.TrimSpace(c.cfg.UserDNTemplate); tmpl != "" {
		id.DN = strings.ReplaceAll(tmpl, "%s", ldap.EscapeDN(username))
	} else {
		if err := c.bindService(conn); err != nil {
			return nil, err
		}
		found, err := c.searchUser(conn, username)
		if err != nil {
			return nil, err
		}
		id = found
	}

	// Verify the password with a bind as the user.
	if err := conn.Bind(id.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("bind as %s: %w", id.DN, err)
	}

	// Group lookup needs the service account again (the user may not be able
	// to read the group tree).
	if c.cfg.GroupBaseDN != "" && c.cfg.GroupFilter != "" {
		if err := c.bindService(conn); err != nil {
			// Fall back to the user's own binding rather than failing login.
			_ = err
		}
		groups, err := c.searchGroups(conn, id.DN, id.Username)
		if err == nil {
			id.Groups = groups
		}
	}

	id.IsAdmin = matchesAny(id.Groups, c.cfg.AdminGroups) || matchesAny([]string{id.DN}, c.cfg.AdminGroups)
	if len(c.cfg.AllowedGroups) > 0 &&
		!matchesAny(id.Groups, c.cfg.AllowedGroups) && !matchesAny([]string{id.DN}, c.cfg.AllowedGroups) {
		return nil, ErrNotAllowed
	}
	if id.DisplayName == "" {
		id.DisplayName = username
	}
	return id, nil
}

// searchUser finds a user entry with the configured filter.
func (c *Client) searchUser(conn *ldap.Conn, username string) (*Identity, error) {
	filter := c.cfg.UserFilter
	if filter == "" {
		filter = "(uid=%s)"
	}
	filter = strings.ReplaceAll(filter, "%s", ldap.EscapeFilter(username))

	attrs := []string{"dn"}
	for _, a := range []string{c.cfg.AttrUsername, c.cfg.AttrDisplayName, c.cfg.AttrEmail, "memberOf"} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	req := ldap.NewSearchRequest(c.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(c.timeout().Seconds()), false, filter, attrs, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("search for user %q: %w", username, err)
	}
	switch len(res.Entries) {
	case 0:
		return nil, ErrInvalidCredentials
	case 1:
	default:
		return nil, fmt.Errorf("user filter matched %d entries for %q; make it more specific",
			len(res.Entries), username)
	}
	e := res.Entries[0]
	id := &Identity{
		DN:       e.DN,
		Username: firstNonEmpty(e.GetAttributeValue(c.cfg.AttrUsername), username),
	}
	if c.cfg.AttrDisplayName != "" {
		id.DisplayName = e.GetAttributeValue(c.cfg.AttrDisplayName)
	}
	if c.cfg.AttrEmail != "" {
		id.Email = e.GetAttributeValue(c.cfg.AttrEmail)
	}
	// Active Directory publishes memberOf directly on the user entry.
	id.Groups = append(id.Groups, e.GetAttributeValues("memberOf")...)
	return id, nil
}

// searchGroups resolves group membership for a user DN.
func (c *Client) searchGroups(conn *ldap.Conn, userDN, username string) ([]string, error) {
	filter := c.cfg.GroupFilter
	filter = strings.ReplaceAll(filter, "%d", ldap.EscapeFilter(userDN))
	filter = strings.ReplaceAll(filter, "%s", ldap.EscapeFilter(userDN))
	filter = strings.ReplaceAll(filter, "%u", ldap.EscapeFilter(username))

	attr := c.cfg.AttrGroup
	if attr == "" {
		attr = "cn"
	}
	req := ldap.NewSearchRequest(c.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, int(c.timeout().Seconds()), false, filter, []string{"dn", attr}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("group search: %w", err)
	}
	var groups []string
	for _, e := range res.Entries {
		groups = append(groups, e.DN)
		if v := e.GetAttributeValue(attr); v != "" {
			groups = append(groups, v)
		}
	}
	return groups, nil
}

// matchesAny compares group values case-insensitively against a wanted list.
// Both full DNs and bare CNs are accepted on either side.
func matchesAny(have, want []string) bool {
	if len(have) == 0 || len(want) == 0 {
		return false
	}
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	cn := func(s string) string {
		for _, part := range strings.Split(s, ",") {
			p := strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(p), "cn=") {
				return norm(p[3:])
			}
		}
		return norm(s)
	}
	set := map[string]bool{}
	for _, h := range have {
		set[norm(h)] = true
		set[cn(h)] = true
	}
	for _, w := range want {
		if set[norm(w)] || set[cn(w)] {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
