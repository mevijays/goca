package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/secret"
)

type setupFlags struct {
	out            string
	dataDir        string
	listen         string
	port           int
	baseURL        string
	authMode       string
	adminUser      string
	adminPass      string
	nonInteractive bool
	force          bool

	dbDriver   string
	dbHost     string
	dbPort     int
	dbName     string
	dbUser     string
	dbPassword string
	dbSSLMode  string

	ldapEnabled  bool
	ldapURL      string
	ldapStartTLS bool
	ldapInsecure bool
	ldapBindDN   string
	ldapBindPass string
	ldapBaseDN   string
	ldapFilter   string
	ldapDNTmpl   string
	ldapGroupDN  string
	ldapGroupF   string
	ldapAdminG   []string
	ldapAllowG   []string

	oidcEnabled      bool
	oidcIssuerURL    string
	oidcClientID     string
	oidcClientSecret string
	oidcRedirectURL  string
	oidcScopes       []string
	oidcInsecure     bool
	oidcClaimUser    string
	oidcClaimName    string
	oidcClaimEmail   string
	oidcClaimGroups  string
	oidcAdminG       []string
	oidcAllowG       []string

	certDays   int
	caDays     int
	crlDays    int
	keyType    string
	sessionTTL time.Duration

	withCA    bool
	caName    string
	caCN      string
	caOrg     string
	caCountry string
}

func newSetupCmd() *cobra.Command {
	f := &setupFlags{}
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Generate the configuration, database and administrator account",
		Long: strings.TrimSpace(`
Creates everything goca needs to run:

  * a config file holding the server, auth and CA defaults
  * a 256-bit master key that encrypts private keys stored in the database
  * a session signing key
  * the database and its schema - SQLite by default, or PostgreSQL when asked for
  * a local administrator account (the break-glass login, always available
    even when the directory server or SSO provider is down)
  * optionally, LDAP and/or OIDC/SSO (Dex, Keycloak, Okta, Azure Entra ID, ...)
  * optionally, your first certificate authority

Run it interactively for a guided wizard, or pass --non-interactive with flags
for unattended installs.`),
		Example: strings.TrimSpace(`
  # Guided setup
  goca setup

  # Unattended, local auth only
  goca setup --non-interactive --admin-user admin --admin-password 'S3cret!!' \
      --port 8080 --base-url https://ca.example.com

  # Unattended with PostgreSQL instead of the default SQLite
  goca setup --non-interactive --admin-user admin --admin-password 'S3cret!!' \
      --database-driver postgres --db-host db.example.com --db-name goca \
      --db-user goca --db-password 'S3cret!!' --db-sslmode require

  # Unattended with LDAP
  goca setup --non-interactive --auth-mode both \
      --admin-user admin --admin-password 'S3cret!!' \
      --ldap --ldap-url ldaps://ldap.example.com:636 \
      --ldap-bind-dn 'cn=svc-ca,ou=svc,dc=example,dc=com' \
      --ldap-bind-password 'bindpw' \
      --ldap-base-dn 'ou=people,dc=example,dc=com' \
      --ldap-user-filter '(&(objectClass=person)(uid=%s))' \
      --ldap-group-base-dn 'ou=groups,dc=example,dc=com' \
      --ldap-admin-group 'cn=ca-admins,ou=groups,dc=example,dc=com'

  # Unattended with OIDC/SSO (Dex, Keycloak, Okta, Azure Entra ID, ...)
  goca setup --non-interactive \
      --admin-user admin --admin-password 'S3cret!!' \
      --base-url https://ca.example.com \
      --oidc --oidc-issuer-url https://dex.example.com \
      --oidc-client-id goca --oidc-client-secret 'S3cret!!' \
      --oidc-admin-group ca-admins`),
		RunE: func(cmd *cobra.Command, _ []string) error { return runSetup(cmd.Context(), f) },
	}

	fl := cmd.Flags()
	fl.StringVarP(&f.out, "out", "o", "", "where to write config.yaml")
	fl.StringVar(&f.dataDir, "data-dir", "", "directory for the database and generated files")
	fl.StringVar(&f.listen, "listen", "0.0.0.0", "address the web portal binds to")
	fl.IntVar(&f.port, "port", 8080, "port the web portal listens on")
	fl.StringVar(&f.baseURL, "base-url", "", "external URL of the portal (used in CRL/OCSP URLs)")
	fl.StringVar(&f.authMode, "auth-mode", "", "local, ldap or both - only governs local/LDAP; OIDC is toggled separately with --oidc")
	fl.StringVar(&f.adminUser, "admin-user", "admin", "local administrator username")
	fl.StringVar(&f.adminPass, "admin-password", "", "local administrator password (generated when omitted)")
	fl.BoolVar(&f.nonInteractive, "non-interactive", false, "never prompt; use flags and defaults")
	fl.BoolVar(&f.force, "force", false, "overwrite an existing config file")
	fl.DurationVar(&f.sessionTTL, "session-ttl", 8*time.Hour, "how long a portal session lasts")

	fl.StringVar(&f.dbDriver, "database-driver", "sqlite", "storage backend: sqlite or postgres")
	fl.StringVar(&f.dbHost, "db-host", "", "PostgreSQL host (required when --database-driver=postgres)")
	fl.IntVar(&f.dbPort, "db-port", 5432, "PostgreSQL port")
	fl.StringVar(&f.dbName, "db-name", "goca", "PostgreSQL database name")
	fl.StringVar(&f.dbUser, "db-user", "goca", "PostgreSQL user")
	fl.StringVar(&f.dbPassword, "db-password", "", "PostgreSQL password (encrypted in the config)")
	fl.StringVar(&f.dbSSLMode, "db-sslmode", "require", "PostgreSQL SSL mode: disable, require, verify-ca or verify-full")

	fl.BoolVar(&f.ldapEnabled, "ldap", false, "enable LDAP authentication")
	fl.StringVar(&f.ldapURL, "ldap-url", "", "ldap:// or ldaps:// URL")
	fl.BoolVar(&f.ldapStartTLS, "ldap-starttls", false, "issue StartTLS after connecting")
	fl.BoolVar(&f.ldapInsecure, "ldap-insecure", false, "skip LDAP TLS certificate verification")
	fl.StringVar(&f.ldapBindDN, "ldap-bind-dn", "", "service account DN used to search for users")
	fl.StringVar(&f.ldapBindPass, "ldap-bind-password", "", "service account password (encrypted in the config)")
	fl.StringVar(&f.ldapBaseDN, "ldap-base-dn", "", "search base for users")
	fl.StringVar(&f.ldapFilter, "ldap-user-filter", "(&(objectClass=person)(uid=%s))", "user search filter, %s = username")
	fl.StringVar(&f.ldapDNTmpl, "ldap-user-dn-template", "", "bind DN template instead of searching, e.g. uid=%s,ou=people,dc=x")
	fl.StringVar(&f.ldapGroupDN, "ldap-group-base-dn", "", "search base for groups")
	fl.StringVar(&f.ldapGroupF, "ldap-group-filter", "(&(objectClass=groupOfNames)(member=%s))", "group filter, %s = user DN")
	fl.StringSliceVar(&f.ldapAdminG, "ldap-admin-group", nil, "group whose members get the admin role (repeatable)")
	fl.StringSliceVar(&f.ldapAllowG, "ldap-allowed-group", nil, "restrict login to these groups (repeatable)")

	fl.BoolVar(&f.oidcEnabled, "oidc", false, "enable OIDC/SSO authentication (Dex, Keycloak, Okta, Azure Entra ID, ...)")
	fl.StringVar(&f.oidcIssuerURL, "oidc-issuer-url", "", "the provider's issuer URL (OIDC discovery is fetched from <url>/.well-known/openid-configuration)")
	fl.StringVar(&f.oidcClientID, "oidc-client-id", "", "OAuth2 client ID registered with the provider")
	fl.StringVar(&f.oidcClientSecret, "oidc-client-secret", "", "OAuth2 client secret (encrypted in the config)")
	fl.StringVar(&f.oidcRedirectURL, "oidc-redirect-url", "", "callback URL registered with the provider (default: <base-url>/auth/oidc/callback)")
	fl.StringSliceVar(&f.oidcScopes, "oidc-scope", nil, "OAuth2 scopes to request (default: openid, profile, email)")
	fl.BoolVar(&f.oidcInsecure, "oidc-insecure", false, "skip TLS certificate verification talking to the issuer (lab use only)")
	fl.StringVar(&f.oidcClaimUser, "oidc-claim-username", "", "ID token claim for the username (default: preferred_username)")
	fl.StringVar(&f.oidcClaimName, "oidc-claim-display-name", "", "ID token claim for the display name (default: name)")
	fl.StringVar(&f.oidcClaimEmail, "oidc-claim-email", "", "ID token claim for the email address (default: email)")
	fl.StringVar(&f.oidcClaimGroups, "oidc-claim-groups", "", "ID token claim for group membership (default: groups)")
	fl.StringSliceVar(&f.oidcAdminG, "oidc-admin-group", nil, "group whose members get the admin role (repeatable)")
	fl.StringSliceVar(&f.oidcAllowG, "oidc-allowed-group", nil, "restrict login to these groups (repeatable)")

	fl.IntVar(&f.certDays, "default-cert-days", 397, "default validity for issued certificates")
	fl.IntVar(&f.caDays, "default-ca-days", 3650, "default validity for new authorities")
	fl.IntVar(&f.crlDays, "crl-days", 7, "how long a generated CRL stays valid")
	fl.StringVar(&f.keyType, "default-key-type", "rsa-2048", "default key type for issued certificates")

	fl.BoolVar(&f.withCA, "with-ca", false, "also create the first certificate authority")
	fl.StringVar(&f.caName, "ca-name", "", "display name of the first authority")
	fl.StringVar(&f.caCN, "ca-common-name", "", "common name of the first authority")
	fl.StringVar(&f.caOrg, "ca-organization", "", "organization of the first authority")
	fl.StringVar(&f.caCountry, "ca-country", "", "country code of the first authority")

	return cmd
}

func runSetup(ctx context.Context, f *setupFlags) error {
	guided := !f.nonInteractive && interactive()

	fmt.Println()
	fmt.Println("  goca setup")
	fmt.Println("  ══════════")
	if guided {
		fmt.Println("  Press enter to accept the value in brackets.")
	}

	cfg := config.Default()

	// ---- config location ----
	outPath := f.out
	if outPath == "" {
		outPath = config.DefaultConfigPath()
	}
	if guided {
		outPath = ask("Config file location", outPath)
	}
	if _, err := os.Stat(outPath); err == nil && !f.force {
		if !guided {
			return fmt.Errorf("%s already exists; pass --force to overwrite", outPath)
		}
		if !askYesNo(fmt.Sprintf("%s exists. Overwrite it?", outPath), false) {
			return errors.New("setup cancelled")
		}
	}

	// ---- storage ----
	section("Storage")
	dataDir := f.dataDir
	if dataDir == "" {
		dataDir = filepath.Dir(outPath)
		if filepath.Base(dataDir) == "goca" && strings.HasPrefix(dataDir, "/etc") {
			dataDir = config.DefaultDataDir()
		}
	}
	if guided {
		dataDir = ask("Data directory", dataDir)
	}
	cfg.DataDir = dataDir
	kv("data directory", cfg.DataDir)

	driver := firstNonEmpty(f.dbDriver, string(config.DBDriverSQLite))
	if guided {
		driver = askChoice("Database backend", []string{"sqlite", "postgres"}, driver)
	}
	cfg.Database.Driver = config.DatabaseDriver(driver)

	dbPassword := f.dbPassword
	if cfg.Database.IsPostgres() {
		d := &cfg.Database
		d.Host = f.dbHost
		d.Port = f.dbPort
		d.Name = f.dbName
		d.User = f.dbUser
		d.SSLMode = f.dbSSLMode

		if guided {
			fmt.Println()
			d.Host = askRequired("  PostgreSQL host", d.Host)
			d.Port = askInt("  PostgreSQL port", firstNonZero(d.Port, 5432))
			d.Name = askRequired("  Database name", firstNonEmpty(d.Name, "goca"))
			d.User = askRequired("  Database user", firstNonEmpty(d.User, "goca"))
			pw, err := askPassword("  Database password", false)
			if err != nil {
				return err
			}
			if pw != "" {
				dbPassword = pw
			}
			d.SSLMode = askChoice("  SSL mode",
				[]string{"require", "disable", "verify-ca", "verify-full"}, firstNonEmpty(d.SSLMode, "require"))
		}
		if d.Host == "" {
			return errors.New("--db-host is required when --database-driver=postgres")
		}
		if d.Name == "" {
			return errors.New("--db-name is required when --database-driver=postgres")
		}
		if d.User == "" {
			return errors.New("--db-user is required when --database-driver=postgres")
		}
		if d.Port == 0 {
			d.Port = 5432
		}
		if d.SSLMode == "" {
			d.SSLMode = "require"
		}
		// Stashed until the master key exists; encrypted just below, same as
		// the LDAP bind password.
		d.Password = dbPassword
		kv("database", fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=%s", d.User, d.Host, d.Port, d.Name, d.SSLMode))
	} else {
		cfg.Database.Driver = config.DBDriverSQLite
		cfg.DBPath = filepath.Join(dataDir, "goca.db")
		if guided {
			cfg.DBPath = ask("SQLite database file", cfg.DBPath)
		}
		kv("database", cfg.DBPath)
	}

	// ---- web server ----
	section("Web portal")
	cfg.Server.Listen = f.listen
	cfg.Server.Port = f.port
	if guided {
		cfg.Server.Listen = ask("Bind address", cfg.Server.Listen)
		cfg.Server.Port = askInt("Port", cfg.Server.Port)
	}
	base := f.baseURL
	if base == "" {
		host := cfg.Server.Listen
		if host == "0.0.0.0" || host == "" || host == "::" {
			host = "localhost"
		}
		base = fmt.Sprintf("http://%s:%d", host, cfg.Server.Port)
	}
	if guided {
		base = ask("External base URL (used inside certificates for CRL URLs)", base)
	}
	if _, err := url.Parse(base); err != nil {
		return fmt.Errorf("base URL %q is not a valid URL: %w", base, err)
	}
	cfg.Server.BaseURL = strings.TrimRight(base, "/")
	cfg.Security.SecureCookies = strings.HasPrefix(cfg.Server.BaseURL, "https://")
	cfg.Security.SessionTTL = f.sessionTTL
	kv("listen", cfg.Addr())
	kv("base URL", cfg.Server.BaseURL)

	// ---- authentication ----
	section("Authentication")
	mode := f.authMode
	if mode == "" {
		mode = "local"
	}
	if guided {
		mode = askChoice("How should portal users sign in?",
			[]string{"local", "ldap", "both"}, mode)
	}
	cfg.Auth.Mode = config.AuthMode(mode)

	wantLDAP := f.ldapEnabled || mode == "ldap" || mode == "both"
	if wantLDAP {
		l := &cfg.Auth.LDAP
		l.Enabled = true
		l.URL = f.ldapURL
		l.StartTLS = f.ldapStartTLS
		l.InsecureSkipVerify = f.ldapInsecure
		l.BindDN = f.ldapBindDN
		l.BaseDN = f.ldapBaseDN
		l.UserFilter = f.ldapFilter
		l.UserDNTemplate = f.ldapDNTmpl
		l.GroupBaseDN = f.ldapGroupDN
		l.GroupFilter = f.ldapGroupF
		l.AdminGroups = f.ldapAdminG
		l.AllowedGroups = f.ldapAllowG
		bindPass := f.ldapBindPass

		if guided {
			fmt.Println()
			l.URL = askRequired("  LDAP URL (ldap://host:389 or ldaps://host:636)", l.URL)
			if strings.HasPrefix(strings.ToLower(l.URL), "ldap://") {
				l.StartTLS = askYesNo("  Upgrade the connection with StartTLS?", l.StartTLS)
			}
			if strings.HasPrefix(strings.ToLower(l.URL), "ldaps://") || l.StartTLS {
				l.InsecureSkipVerify = askYesNo("  Skip TLS certificate verification (lab use only)?", l.InsecureSkipVerify)
				if !l.InsecureSkipVerify {
					l.CACertFile = ask("  CA certificate file for the LDAP server (blank = system roots)", l.CACertFile)
				}
			}
			l.BindDN = ask("  Service account bind DN (blank = anonymous search)", l.BindDN)
			if l.BindDN != "" {
				pw, err := askPassword("  Service account password", false)
				if err != nil {
					return err
				}
				bindPass = pw
			}
			l.BaseDN = askRequired("  User search base DN", l.BaseDN)
			l.UserFilter = ask("  User search filter (%s = username)", l.UserFilter)
			l.AttrUsername = ask("  Username attribute", firstNonEmpty(l.AttrUsername, "uid"))
			l.AttrDisplayName = ask("  Display name attribute", firstNonEmpty(l.AttrDisplayName, "cn"))
			l.AttrEmail = ask("  Email attribute", firstNonEmpty(l.AttrEmail, "mail"))
			l.GroupBaseDN = ask("  Group search base DN (blank to skip group lookups)", l.BaseDN)
			if l.GroupBaseDN != "" {
				l.GroupFilter = ask("  Group filter (%s = user DN)", l.GroupFilter)
				l.AttrGroup = ask("  Group name attribute", firstNonEmpty(l.AttrGroup, "cn"))
				if g := ask("  Admin group DN or CN (comma separated, blank for none)",
					strings.Join(l.AdminGroups, ",")); g != "" {
					l.AdminGroups = splitCSV(g)
				}
				if g := ask("  Restrict login to these groups (comma separated, blank = any user)",
					strings.Join(l.AllowedGroups, ",")); g != "" {
					l.AllowedGroups = splitCSV(g)
				}
			}
		}
		if l.URL == "" {
			return errors.New("--ldap-url is required when LDAP is enabled")
		}
		if l.AttrUsername == "" {
			l.AttrUsername = "uid"
		}
		if l.AttrDisplayName == "" {
			l.AttrDisplayName = "cn"
		}
		if l.AttrEmail == "" {
			l.AttrEmail = "mail"
		}
		if l.AttrGroup == "" {
			l.AttrGroup = "cn"
		}
		if l.Timeout == 0 {
			l.Timeout = 10 * time.Second
		}
		// Stashed until the master key exists; encrypted just below.
		l.BindPassword = bindPass
	}

	wantOIDC := f.oidcEnabled
	if guided {
		fmt.Println()
		wantOIDC = askYesNo("Enable OIDC / single sign-on (Dex, Keycloak, Okta, Azure Entra ID, ...)?", wantOIDC)
	}
	if wantOIDC {
		o := &cfg.Auth.OIDC
		o.Enabled = true
		o.IssuerURL = f.oidcIssuerURL
		o.ClientID = f.oidcClientID
		o.RedirectURL = f.oidcRedirectURL
		o.Scopes = f.oidcScopes
		o.InsecureSkipVerify = f.oidcInsecure
		o.ClaimUsername = f.oidcClaimUser
		o.ClaimDisplayName = f.oidcClaimName
		o.ClaimEmail = f.oidcClaimEmail
		o.ClaimGroups = f.oidcClaimGroups
		o.AdminGroups = f.oidcAdminG
		o.AllowedGroups = f.oidcAllowG
		clientSecret := f.oidcClientSecret

		if guided {
			fmt.Println()
			o.IssuerURL = askRequired(
				"  Issuer URL (e.g. https://dex.example.com, or https://login.microsoftonline.com/<tenant-id>/v2.0)",
				o.IssuerURL)
			o.ClientID = askRequired("  Client ID", o.ClientID)
			pw, err := askPassword("  Client secret", false)
			if err != nil {
				return err
			}
			if pw != "" {
				clientSecret = pw
			}
			defaultRedirect := firstNonEmpty(o.RedirectURL, strings.TrimRight(cfg.Server.BaseURL, "/")+"/auth/oidc/callback")
			o.RedirectURL = ask("  Redirect URL (must be registered with the provider exactly)", defaultRedirect)
			if s := ask("  Scopes (space separated)", firstNonEmpty(strings.Join(o.Scopes, " "), "openid profile email")); s != "" {
				o.Scopes = strings.Fields(s)
			}
			o.InsecureSkipVerify = askYesNo("  Skip TLS certificate verification talking to the issuer (lab use only)?", o.InsecureSkipVerify)
			o.ClaimUsername = ask("  Username claim", firstNonEmpty(o.ClaimUsername, "preferred_username"))
			o.ClaimDisplayName = ask("  Display name claim", firstNonEmpty(o.ClaimDisplayName, "name"))
			o.ClaimEmail = ask("  Email claim", firstNonEmpty(o.ClaimEmail, "email"))
			o.ClaimGroups = ask("  Groups claim", firstNonEmpty(o.ClaimGroups, "groups"))
			if g := ask("  Admin group name or ID (comma separated, blank for none)",
				strings.Join(o.AdminGroups, ",")); g != "" {
				o.AdminGroups = splitCSV(g)
			}
			if g := ask("  Restrict login to these groups (comma separated, blank = any authenticated user)",
				strings.Join(o.AllowedGroups, ",")); g != "" {
				o.AllowedGroups = splitCSV(g)
			}
		}
		if o.IssuerURL == "" {
			return errors.New("--oidc-issuer-url is required when OIDC is enabled")
		}
		if o.ClientID == "" {
			return errors.New("--oidc-client-id is required when OIDC is enabled")
		}
		if o.RedirectURL == "" {
			o.RedirectURL = strings.TrimRight(cfg.Server.BaseURL, "/") + "/auth/oidc/callback"
		}
		// Stashed until the master key exists; encrypted just below.
		o.ClientSecret = clientSecret
		kv("OIDC issuer", o.IssuerURL)
	}

	// ---- local administrator ----
	adminUser := f.adminUser
	adminPass := f.adminPass
	generated := false
	if guided {
		fmt.Println()
		adminUser = ask("Local administrator username (break-glass account)", adminUser)
		if askYesNo("  Set the administrator password now?", true) {
			pw, err := askPassword("  Password", true)
			if err != nil {
				return err
			}
			adminPass = pw
		}
	}
	if adminPass == "" {
		pw, err := auth.GeneratePassword(20)
		if err != nil {
			return err
		}
		adminPass = pw
		generated = true
	}
	if err := auth.ValidatePassword(adminPass); err != nil {
		return err
	}
	hash, err := auth.HashPassword(adminPass)
	if err != nil {
		return err
	}
	cfg.Auth.LocalAdmin = config.LocalAdmin{Username: adminUser, PasswordHash: hash}

	// ---- CA defaults ----
	section("Certificate defaults")
	cfg.CA.DefaultCertDays = f.certDays
	cfg.CA.DefaultCADays = f.caDays
	cfg.CA.CRLDays = f.crlDays
	cfg.CA.DefaultKeyType = f.keyType
	cfg.CA.AllowUserRequest = true
	if guided {
		cfg.CA.DefaultCertDays = askInt("Default certificate validity (days)", cfg.CA.DefaultCertDays)
		cfg.CA.DefaultCADays = askInt("Default authority validity (days)", cfg.CA.DefaultCADays)
		cfg.CA.CRLDays = askInt("CRL validity (days)", cfg.CA.CRLDays)
		types := make([]string, len(pki.KeyTypes))
		for i, k := range pki.KeyTypes {
			types[i] = string(k)
		}
		cfg.CA.DefaultKeyType = askChoice("Default key type for issued certificates", types, cfg.CA.DefaultKeyType)
	}
	if _, err := pki.ParseKeyType(cfg.CA.DefaultKeyType); err != nil {
		return err
	}
	// CRL distribution points are set per authority rather than globally, so
	// each CA can publish its own URL.
	kv("certificate validity", fmt.Sprintf("%d days", cfg.CA.DefaultCertDays))
	kv("authority validity", fmt.Sprintf("%d days", cfg.CA.DefaultCADays))
	kv("default key type", cfg.CA.DefaultKeyType)

	// ---- secrets, then write ----
	if err := cfg.GenerateSecrets(); err != nil {
		return err
	}
	if cfg.Auth.LDAP.Enabled && cfg.Auth.LDAP.BindPassword != "" {
		key, err := cfg.MasterKeyBytes()
		if err != nil {
			return err
		}
		box, err := secret.NewBox(key)
		if err != nil {
			return err
		}
		enc, err := box.EncryptString(cfg.Auth.LDAP.BindPassword)
		if err != nil {
			return err
		}
		cfg.Auth.LDAP.BindPassword = enc
	}
	if cfg.Database.IsPostgres() && cfg.Database.Password != "" {
		key, err := cfg.MasterKeyBytes()
		if err != nil {
			return err
		}
		box, err := secret.NewBox(key)
		if err != nil {
			return err
		}
		enc, err := box.EncryptString(cfg.Database.Password)
		if err != nil {
			return err
		}
		cfg.Database.Password = enc
	}
	if cfg.Auth.OIDC.Enabled && cfg.Auth.OIDC.ClientSecret != "" {
		key, err := cfg.MasterKeyBytes()
		if err != nil {
			return err
		}
		box, err := secret.NewBox(key)
		if err != nil {
			return err
		}
		enc, err := box.EncryptString(cfg.Auth.OIDC.ClientSecret)
		if err != nil {
			return err
		}
		cfg.Auth.OIDC.ClientSecret = enc
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data directory %s: %w", cfg.DataDir, err)
	}
	if err := cfg.Save(outPath); err != nil {
		return err
	}

	section("Writing")
	ok("config written to %s (mode 0600)", outPath)

	// ---- database ----
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	ok("database initialised at %s", cfg.DatabaseSummary())

	svc, err := ca.New(cfg, st)
	if err != nil {
		return err
	}
	mgr, err := auth.NewManager(cfg, st, svc.Box())
	if err != nil {
		return err
	}
	if err := mgr.EnsureLocalAdmin(ctx); err != nil {
		return err
	}
	ok("local administrator %q created", adminUser)
	_ = st.Audit(ctx, adminUser, "setup.complete", outPath,
		fmt.Sprintf("auth=%s port=%d", cfg.Auth.Mode, cfg.Server.Port), "")

	// ---- optional first CA ----
	makeCA := f.withCA
	if guided && !makeCA {
		fmt.Println()
		makeCA = askYesNo("Create your first certificate authority now?", true)
	}
	if makeCA {
		section("First certificate authority")
		in := ca.CreateCAInput{
			Name:        f.caName,
			Subject:     pki.Subject{CommonName: f.caCN, Organization: f.caOrg, Country: f.caCountry},
			Days:        cfg.CA.DefaultCADays,
			KeyType:     string(pki.KeyRSA4096),
			PathLen:     1,
			MakeDefault: true,
			Actor:       adminUser,
		}
		if guided {
			in.Subject.CommonName = askRequired("Common name (CN)", firstNonEmpty(in.Subject.CommonName, "goca Root CA"))
			in.Name = ask("Display name", firstNonEmpty(in.Name, in.Subject.CommonName))
			in.Subject.Organization = ask("Organization (O)", in.Subject.Organization)
			in.Subject.OrganizationalUnit = ask("Organizational unit (OU)", "")
			in.Subject.Country = ask("Country code (C)", in.Subject.Country)
			in.Subject.Province = ask("State / province (ST)", "")
			in.Subject.Locality = ask("Locality (L)", "")
			types := make([]string, len(pki.KeyTypes))
			for i, k := range pki.KeyTypes {
				types[i] = string(k)
			}
			in.KeyType = askChoice("Key type", types, string(pki.KeyRSA4096))
			in.Days = askInt("Validity (days)", in.Days)
			if askYesNo("Embed a CRL distribution point in issued certificates?", true) {
				slug := ca.Slugify(firstNonEmpty(in.Name, in.Subject.CommonName))
				in.CRLDistPoints = []string{fmt.Sprintf("%s/public/crl/%s.crl", cfg.Server.BaseURL, slug)}
			}
		} else if in.Subject.CommonName == "" {
			in.Subject.CommonName = "goca Root CA"
		}
		created, err := svc.CreateCA(ctx, in)
		if err != nil {
			warn("could not create the authority: %v", err)
			warn("run `goca ca create --wizard` once setup finishes")
		} else {
			ok("authority %q created (serial %s)", created.Name, created.SerialHex)
			info("valid until %s", created.NotAfter.Format("2006-01-02"))
			info("download: %s/public/ca/%s.crt", cfg.Server.BaseURL, created.Slug)
		}
	}

	// ---- summary ----
	section("Done")
	kv("config", outPath)
	kv("database", cfg.DatabaseSummary())
	kv("admin user", adminUser)
	if cfg.Auth.OIDC.Enabled {
		kv("OIDC issuer", cfg.Auth.OIDC.IssuerURL)
	}
	if generated {
		fmt.Println()
		fmt.Printf("  \033[1mGenerated administrator password: %s\033[0m\n", adminPass)
		fmt.Println("  Save it now - it is stored only as a bcrypt hash.")
	}
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Printf("    goca run web --port=%d          start the portal\n", cfg.Server.Port)
	fmt.Printf("    goca install web --port=%d      install it as a service\n", cfg.Server.Port)
	if !makeCA {
		fmt.Println("    goca ca create --wizard          create your first authority")
	}
	fmt.Println()
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
