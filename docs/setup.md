# Setting up goca

This covers everything from a fresh binary to a running portal: building,
`goca setup` (interactive and unattended), the config file it produces,
running the web portal, installing it as a service, TLS, LDAP, and upgrading
an existing install. For day-to-day CLI usage once you're running, see
[USAGE.md](usage.md). For what goca does, see [README.md](index.md).

## Contents

- [Requirements](#requirements)
- [Building](#building)
- [Interactive setup](#interactive-setup)
- [Unattended setup](#unattended-setup)
- [What setup produces](#what-setup-produces)
- [The config file](#the-config-file)
- [Database](#database)
- [Running the portal](#running-the-portal)
- [Installing as a service](#installing-as-a-service)
- [TLS](#tls)
- [LDAP setup](#ldap-setup)
- [Single sign-on (OIDC) setup](#single-sign-on-oidc-setup)
- [First certificate authority](#first-certificate-authority)
- [Running underneath an existing CA](#running-underneath-an-existing-ca)
- [Trusting the CA on clients](#trusting-the-ca-on-clients)
- [Upgrading](#upgrading)
- [Backup and disaster recovery](#backup-and-disaster-recovery)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- **To build:** Go 1.22 or later. No other build-time dependencies — both database
  drivers are pure Go (`modernc.org/sqlite` and `jackc/pgx`), so there's no cgo,
  no libc pinning, and nothing else to install.
- **To run:** nothing beyond the binary and, if you choose PostgreSQL, a reachable
  server. By default the database is a single SQLite file next to the binary; the
  web UI (HTML/CSS/JS) is compiled in with `go:embed` either way.
- **Disk:** trivial. A SQLite database with thousands of certificates and their
  keys is typically a few tens of megabytes.
- **Network:** the portal needs an open TCP port (8080 by default). LDAP, if
  used, needs outbound access to your directory server (389/636 typically).

## Building

```bash
go build -o goca .
```

Cross-compiling works the same as any Go program, since there's no cgo:

```bash
GOOS=linux   GOARCH=amd64 go build -o goca-linux-amd64   .
GOOS=linux   GOARCH=arm64 go build -o goca-linux-arm64   .
GOOS=darwin  GOARCH=arm64 go build -o goca-darwin-arm64  .
GOOS=windows GOARCH=amd64 go build -o goca-windows.exe   .
```

Build the binary once per platform and copy it wherever it needs to run — the
web assets and SQLite driver travel with it.

## Interactive setup

```bash
./goca setup
```

This is a guided wizard. It asks for, in order:

1. **Config file location** — defaults to `~/.goca/config.yaml`, or
   `/etc/goca/config.yaml` if you're running as root.
2. **Data directory and database path** — where `goca.db` lives.
3. **Web portal bind address and port**, and the **external base URL** (used
   inside issued certificates for CRL/OCSP distribution points, so get this
   right if certificates need to carry a working CRL URL).
4. **Authentication mode** — local, LDAP, or both. Choosing LDAP or both walks
   you through the full directory configuration (see
   [LDAP setup](#ldap-setup)). Right after, it separately asks whether to
   enable OIDC/SSO too (see [Single sign-on (OIDC) setup](#single-sign-on-oidc-setup))
   - it composes with whatever you picked above rather than being a fourth
     mutually-exclusive choice.
5. **Local administrator** — a username and password for the break-glass
   account that always works, even if LDAP is down. Leave the password blank
   and one is generated and printed once at the end.
6. **Certificate defaults** — default validity for certificates and CAs,
   default key type, CRL validity.
7. **Optionally, your first certificate authority** — see
   [First certificate authority](#first-certificate-authority).

At the end it prints a summary: the config path, the database path, the admin
username, the generated password if one was made, and next-step commands.

Press enter at any prompt to accept the value shown in brackets.

## Unattended setup

Every prompt has a corresponding flag, and `--non-interactive` disables
prompting entirely — anything not given a flag falls back to its default.

```bash
./goca setup --non-interactive \
  --admin-user admin --admin-password 'S3cret!!' \
  --port 8080 --base-url https://ca.example.com \
  --with-ca --ca-common-name "Acme Root CA" --ca-organization Acme --ca-country IN
```

### `goca setup` flags

**General**

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --out` | `~/.goca/config.yaml` (or `/etc/goca/...` as root) | where to write `config.yaml` |
| `--data-dir` | same directory as `--out` | directory for the database and generated files |
| `--non-interactive` | off | never prompt; use flags and defaults |
| `--force` | off | overwrite an existing config file |

**Web portal**

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `0.0.0.0` | address the web portal binds to |
| `--port` | `8080` | port the web portal listens on |
| `--base-url` | `http://<listen>:<port>` | external URL of the portal; used in CRL/OCSP URLs baked into certificates |
| `--session-ttl` | `8h` | how long a portal session lasts |

**Authentication**

| Flag | Default | Meaning |
| --- | --- | --- |
| `--auth-mode` | `local` | `local`, `ldap`, or `both` |
| `--admin-user` | `admin` | local administrator username |
| `--admin-password` | *(generated)* | local administrator password |

**Database** (PostgreSQL flags only matter when `--database-driver postgres`; see [Database](#database))

| Flag | Default | Meaning |
| --- | --- | --- |
| `--database-driver` | `sqlite` | storage backend: `sqlite` or `postgres` |
| `--db-host` | — | PostgreSQL host (required for `postgres`) |
| `--db-port` | `5432` | PostgreSQL port |
| `--db-name` | `goca` | PostgreSQL database name |
| `--db-user` | `goca` | PostgreSQL user |
| `--db-password` | — | PostgreSQL password (encrypted in the config) |
| `--db-sslmode` | `require` | `disable`, `require`, `verify-ca`, or `verify-full` |

**LDAP** (only matters when `--ldap` is set or `--auth-mode` is `ldap`/`both`)

| Flag | Default | Meaning |
| --- | --- | --- |
| `--ldap` | off | enable LDAP authentication |
| `--ldap-url` | — | `ldap://host:389` or `ldaps://host:636` |
| `--ldap-starttls` | off | upgrade an `ldap://` connection with StartTLS |
| `--ldap-insecure` | off | skip TLS certificate verification (lab use only) |
| `--ldap-bind-dn` | — | service account DN used to search for users (blank = anonymous) |
| `--ldap-bind-password` | — | service account password (encrypted in the config) |
| `--ldap-base-dn` | — | search base for users |
| `--ldap-user-filter` | `(&(objectClass=person)(uid=%s))` | user search filter, `%s` = username |
| `--ldap-user-dn-template` | — | bind DN template instead of searching, e.g. `uid=%s,ou=people,dc=x` |
| `--ldap-group-base-dn` | — | search base for groups |
| `--ldap-group-filter` | `(&(objectClass=groupOfNames)(member=%s))` | group filter, `%s` = user DN |
| `--ldap-admin-group` | — | group whose members get the admin role (repeatable) |
| `--ldap-allowed-group` | — | restrict login to these groups (repeatable) |

**OIDC / SSO** (only matters when `--oidc` is set; see [Single sign-on (OIDC) setup](#single-sign-on-oidc-setup))

| Flag | Default | Meaning |
| --- | --- | --- |
| `--oidc` | off | enable OIDC/SSO authentication |
| `--oidc-issuer-url` | — | the provider's issuer URL (discovery is fetched from `<url>/.well-known/openid-configuration`) |
| `--oidc-client-id` | — | OAuth2 client ID registered with the provider |
| `--oidc-client-secret` | — | OAuth2 client secret (encrypted in the config) |
| `--oidc-redirect-url` | `<base-url>/auth/oidc/callback` | callback URL registered with the provider |
| `--oidc-scope` | `openid`, `profile`, `email` | OAuth2 scopes to request (repeatable) |
| `--oidc-insecure` | off | skip TLS certificate verification talking to the issuer (lab use only) |
| `--oidc-claim-username` | `preferred_username` | ID token claim for the username |
| `--oidc-claim-display-name` | `name` | ID token claim for the display name |
| `--oidc-claim-email` | `email` | ID token claim for the email address |
| `--oidc-claim-groups` | `groups` | ID token claim for group membership |
| `--oidc-admin-group` | — | group whose members get the admin role (repeatable) |
| `--oidc-allowed-group` | — | restrict login to these groups (repeatable) |

**Certificate defaults**

| Flag | Default | Meaning |
| --- | --- | --- |
| `--default-cert-days` | `397` | default validity for issued certificates |
| `--default-ca-days` | `3650` | default validity for new authorities |
| `--crl-days` | `7` | how long a generated CRL stays valid |
| `--default-key-type` | `rsa-2048` | default key type for issued certificates |

**First authority**

| Flag | Default | Meaning |
| --- | --- | --- |
| `--with-ca` | off | also create the first certificate authority |
| `--ca-name` | — | display name of the first authority |
| `--ca-common-name` | — | common name of the first authority |
| `--ca-organization` | — | organization of the first authority |
| `--ca-country` | — | country code of the first authority |

With LDAP, a fully unattended example:

```bash
./goca setup --non-interactive --auth-mode both \
    --admin-user admin --admin-password 'S3cret!!' \
    --ldap --ldap-url ldaps://ldap.example.com:636 \
    --ldap-bind-dn 'cn=svc-ca,ou=svc,dc=example,dc=com' \
    --ldap-bind-password 'bindpw' \
    --ldap-base-dn 'ou=people,dc=example,dc=com' \
    --ldap-user-filter '(&(objectClass=person)(uid=%s))' \
    --ldap-group-base-dn 'ou=groups,dc=example,dc=com' \
    --ldap-admin-group 'cn=ca-admins,ou=groups,dc=example,dc=com'
```

With OIDC, a fully unattended example against Dex:

```bash
./goca setup --non-interactive \
    --admin-user admin --admin-password 'S3cret!!' \
    --base-url https://ca.example.com \
    --oidc --oidc-issuer-url https://dex.example.com \
    --oidc-client-id goca --oidc-client-secret 'S3cret!!' \
    --oidc-admin-group ca-admins
```

See [Single sign-on (OIDC) setup](#single-sign-on-oidc-setup) for the details - registering the
client with a provider, what each claim/group flag does, and worked examples
for Dex and Azure Entra ID.

## What setup produces

1. **`config.yaml`**, mode `0600`, holding server settings, the master and
   session encryption keys, the local admin's bcrypt hash, and (if
   configured) the LDAP settings with the bind password encrypted.
2. **A database** with its schema created — a SQLite file (`goca.db` by
   default) unless PostgreSQL was chosen, see [Database](#database).
3. **A local administrator account**, mirrored from the config into the
   database.
4. **Optionally, a first certificate authority**, if `--with-ca` was passed or
   you accepted the wizard's offer.

Re-running `goca setup` against the same `--out` path requires `--force` (or
a "yes" at the interactive overwrite prompt); it does not merge with an
existing file.

## The config file

```yaml
data_dir: /var/lib/goca
db_path: /var/lib/goca/goca.db          # used only when database.driver is sqlite
database:
  driver: sqlite                        # sqlite (default) | postgres
  # host, port, name, user, password, sslmode are set here when driver: postgres
  # (see Database below); password is encrypted with master_key, like bind_password.
server:
  listen: 0.0.0.0
  port: 8080
  base_url: https://ca.example.com
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
security:
  master_key: <base64, 32 bytes>     # encrypts private keys stored in SQLite
  session_key: <base64, 32 bytes>    # signs session cookies
  session_ttl: 8h
  secure_cookies: true
auth:
  mode: both                          # local | ldap | both
  local_admin:
    username: admin
    password_hash: $2a$10$...
  ldap:
    enabled: true
    url: ldaps://ldap.example.com:636
    start_tls: false
    insecure_skip_verify: false
    ca_cert_file: ""
    bind_dn: "cn=svc-ca,ou=svc,dc=example,dc=com"
    bind_password: "enc:v1:...."     # encrypted with master_key
    base_dn: "ou=people,dc=example,dc=com"
    user_filter: "(&(objectClass=person)(uid=%s))"
    user_dn_template: ""
    attr_username: uid
    attr_display_name: cn
    attr_email: mail
    group_base_dn: "ou=groups,dc=example,dc=com"
    group_filter: "(&(objectClass=groupOfNames)(member=%s))"
    attr_group: cn
    admin_groups: ["cn=ca-admins,ou=groups,dc=example,dc=com"]
    allowed_groups: []
    timeout: 10s
  oidc:
    enabled: true
    issuer_url: https://dex.example.com
    client_id: goca
    client_secret: "enc:v1:...."     # encrypted with master_key
    redirect_url: https://ca.example.com/auth/oidc/callback
    scopes: [openid, profile, email]
    insecure_skip_verify: false
    claim_username: ""                # blank = default (preferred_username, falls back to email, sub)
    claim_display_name: ""            # blank = default (name)
    claim_email: ""                   # blank = default (email)
    claim_groups: ""                  # blank = default (groups)
    admin_groups: ["ca-admins"]
    allowed_groups: []
ca:
  default_cert_days: 397
  default_ca_days: 3650
  default_key_type: rsa-2048
  crl_days: 7
  allow_user_request: true
  ocsp_servers: []
  crl_distribution_points: []
```

**Every field can be hand-edited.** goca reloads the config file on every CLI
invocation and on `goca run web` startup, so a change takes effect the next
run. There is no live-reload while the portal is already running — restart
the service after editing.

**Locating it:** goca looks in this order:

1. `--config` / `-c` on the command line
2. the `GOCA_CONFIG` environment variable
3. `~/.goca/config.yaml`
4. `/etc/goca/config.yaml`

The first one that exists wins. There are no other environment-variable
overrides — every other setting lives in the file itself.

**The master key is the one thing you cannot lose.** It's a random 32-byte
key that encrypts every private key stored in the database (CA keys and any
end-entity keys you asked goca to keep). Lose the config file and you can
still read certificates from the database, but every encrypted private key
becomes permanently unrecoverable. Back up `config.yaml` and `goca.db`
together, and protect the config file at least as carefully as you'd protect
a private key directly — mode `0600` is the floor, not the ceiling.

## Database

goca defaults to SQLite: a single file, no server to run, no configuration
beyond a path. `goca setup` picks this unless told otherwise.

For a server-based database instead, choose PostgreSQL — during the wizard
(`Database backend` prompt), or non-interactively:

```bash
goca setup --non-interactive \
    --database-driver postgres \
    --db-host db.example.com --db-port 5432 \
    --db-name goca --db-user goca --db-password 'S3cret!!' \
    --db-sslmode require \
    --admin-user admin --admin-password 'S3cret!!'
```

Key points:

- The database and its schema are created (and, on upgrade, migrated) the same
  way for both backends — there's nothing to run by hand against PostgreSQL
  first beyond having an empty database and a user with rights to it.
- `--db-sslmode` accepts `disable`, `require` (the default), `verify-ca` or
  `verify-full`; use `disable` only for a database on localhost or a private
  network you trust.
- The PostgreSQL password is encrypted with `security.master_key` before being
  written to `config.yaml`, exactly like the LDAP bind password
  (`enc:v1:...` prefix). A hand-edited plaintext password is still accepted,
  and gets encrypted in place the next time goca writes the file.
- Switching backends is not a live migration: pick one at setup time. Moving
  an existing SQLite install to PostgreSQL means re-issuing/re-importing into
  a freshly set-up PostgreSQL-backed instance; there is no `goca` command that
  copies data between the two today.
- [docker-compose.yaml](https://github.com/mevijays/goca/blob/main/docker-compose.yaml) ships an optional PostgreSQL
  service behind the `postgres` profile — see the comments at the top of that
  file.

## Running the portal

```bash
goca run web --port=8080
```

Flags on `run web` override the config file for that invocation only; they
don't rewrite `config.yaml`.

| Flag | Meaning |
| --- | --- |
| `--port` | port to listen on (overrides the config file) |
| `--listen` | address to bind (overrides the config file) |
| `--tls-cert` | serve HTTPS with this certificate |
| `--tls-key` | private key for `--tls-cert` |

The process runs in the foreground and logs to stderr. It handles `SIGINT`
and `SIGTERM` for a graceful shutdown. Open `http://<host>:<port>` and sign in
with the admin account setup created.

## Installing as a service

```bash
sudo goca install web --port=8080 --now
```

This generates a **systemd** unit (Linux) or **launchd** plist (macOS) that
runs this exact binary, from its current path, as the invoking user (or
`--user`), pointed at the config file goca resolved. `--now` reloads the
service manager and starts it immediately.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--port` | the configured port | port the service listens on |
| `--listen` | — | address the service binds to |
| `--user` | current user | unix user to run as |
| `--binary` | this executable | path to the goca binary |
| `--name` | `goca-web` | service unit name |
| `--user-scope` | off | install into the current user's service manager instead of the system one (no root needed) |
| `--now` | off | reload the manager, then enable and start the service |
| `--print` | off | print the unit file instead of installing it |
| `--tls-cert` / `--tls-key` | — | serve HTTPS with this certificate |

Writing to `/etc/systemd/system` or `/Library/LaunchDaemons` needs root — run
under `sudo`, or pass `--user-scope` to install into your own systemd user
instance / `~/Library/LaunchAgents` instead, which needs no elevated
privileges. Without `--now`, `install web` prints the manual follow-up
commands (`systemctl daemon-reload && systemctl enable --now goca-web`, or
the launchd equivalent).

Remove an installed service with:

```bash
sudo goca uninstall web
```

or `goca uninstall web --user-scope` for a user-scoped install. It stops,
disables, and deletes the unit file.

## TLS

Bootstrap a portal certificate with goca itself, then start under it:

```bash
goca cert issue --common-name ca.example.com --san ca.example.com --out ./tls
goca run web --port=8443 --tls-cert=./tls/ca.example.com.crt --tls-key=./tls/ca.example.com.key
```

Set `security.secure_cookies: true` in the config (setup does this
automatically whenever `--base-url` starts with `https://`). Behind a reverse
proxy terminating TLS for you, forward the `X-Forwarded-Proto` header so goca
still marks cookies `Secure` correctly.

## LDAP setup

LDAP can be configured during `goca setup` (interactively or with the
`--ldap-*` flags above), or added later by hand-editing
`auth.ldap` in the config file and restarting the portal.

Key points:

- `auth.mode: both` tries the local admin first, so a directory outage never
  locks you out.
- `admin_groups` grants the admin role to anyone who is a member; without
  it, everyone who authenticates gets the `user` role.
- `allowed_groups`, if non-empty, restricts login to members of at least one
  listed group. Leave it empty to let any directory user who can
  authenticate sign in.
- Group matching accepts a full DN or a bare CN on either side of the
  comparison, and Active Directory's `memberOf` attribute is read
  automatically — no special configuration needed for AD.
- The bind password is encrypted with the master key before being written to
  disk (`enc:v1:...` prefix). If you hand-edit the config with a plaintext
  password, it's still accepted — goca encrypts it in place the next time it
  writes the file.

Verify a configuration before relying on it:

```bash
goca ldap test              # connectivity, service bind, search base
goca ldap login alice       # a full login: prompts for the password,
                             # shows the resolved DN, groups, and role
```

## Single sign-on (OIDC) setup

goca can authenticate portal users against any standards-compliant OpenID
Connect provider - Dex, Keycloak, Okta, Google, Azure Entra ID, or anything
else that publishes OIDC discovery at `<issuer>/.well-known/openid-configuration`.
It's independent of `auth.mode`/LDAP: enable it during `goca setup` (the
wizard asks separately, right after the LDAP section) or with the `--oidc-*`
flags above, or add it later by hand-editing `auth.oidc` in the config file
and restarting the portal.

**Registering goca as a client**, whatever the provider:

1. Create an OAuth2/OIDC client (sometimes called an "application").
2. Set its redirect/callback URL to `<your base_url>/auth/oidc/callback`
   exactly - this must match `auth.oidc.redirect_url` in the config.
3. Note the issuer URL, client ID and client secret; goca needs all three.

**Dex** ([dexidp/dex](https://github.com/dexidp/dex)), a minimal setup with a
static client:

```yaml
# dex config.yaml
issuer: https://dex.example.com
staticClients:
  - id: goca
    secret: <a random secret>
    redirectURIs:
      - https://ca.example.com/auth/oidc/callback
```

```bash
goca setup --non-interactive --admin-user admin --admin-password 'S3cret!!' \
    --base-url https://ca.example.com \
    --oidc --oidc-issuer-url https://dex.example.com \
    --oidc-client-id goca --oidc-client-secret '<the random secret>'
```

**Azure Entra ID:** register an app under Entra ID → App registrations, add
`https://ca.example.com/auth/oidc/callback` as a Web redirect URI, create a
client secret under Certificates & secrets, and use the v2 issuer URL:

```bash
goca setup --non-interactive --admin-user admin --admin-password 'S3cret!!' \
    --base-url https://ca.example.com \
    --oidc --oidc-issuer-url https://login.microsoftonline.com/<tenant-id>/v2.0 \
    --oidc-client-id <application-client-id> \
    --oidc-client-secret '<the client secret value>'
```

Entra ID does not emit a `groups` claim by default - add "Groups" under the
app registration's Token configuration → Optional claims (ID) before setting
`--oidc-admin-group`/`--oidc-allowed-group`, or those will never match.
**Keycloak** and **Okta** work the same way: their issuer URLs are
`https://<host>/realms/<realm>` and `https://<domain>/oauth2/default`
respectively, and both emit a `groups` claim once you add a groups mapper /
authorization server claim for it.

Key points:

- Local login stays available alongside OIDC unless `--auth-mode ldap` turns
  it off - the same flag LDAP-only setups use, since `auth.mode` only ever
  governs local, independent of what's enabled below it. Keeping local on is
  the recommended default: a provider outage or a misconfigured claim
  otherwise locks every admin out at once.
- `oidc_admin_group` (config: `admin_groups`) grants the admin role to
  members of the listed groups; without it, everyone who signs in gets the
  `user` role. `allowed_groups`, if non-empty, restricts login to members of
  at least one listed group - matched case-insensitively against the groups
  claim's values.
- `claim_groups` names which ID token (or userinfo) claim carries group
  membership; leave it unset for the `groups` default. There's no separate
  switch to turn group-based roles off - leaving `admin_groups` and
  `allowed_groups` both empty already has that effect (everyone who signs in
  gets the `user` role, nobody is excluded).
- The username claim defaults to `preferred_username`, falling back to
  `email` then `sub` (guaranteed present per the OIDC spec) if that claim is
  absent - Dex's built-in password database, for example, doesn't emit
  `preferred_username`, so accounts end up keyed by email there.
- The client secret is encrypted with the master key before being written to
  disk (`enc:v1:...` prefix), exactly like the LDAP bind password.
- OIDC discovery happens lazily, on the first actual sign-in attempt through
  it - not at `goca run web` startup or on every CLI command - so a
  temporarily unreachable provider never blocks anything else goca does.
- Verify a configuration by actually signing in: open the portal, click
  **Sign in with SSO**, and complete the provider's login. The Settings page
  (admins only) shows the active issuer, client ID, redirect URL, scopes and
  group configuration - handy for confirming what's actually loaded without
  it echoing the secret back.

## First certificate authority

If you didn't create one during setup:

```bash
goca ca create --wizard
```

or non-interactively:

```bash
goca ca create --name "Acme Root CA" --common-name "Acme Root CA" \
    --organization Acme --country IN --key-type rsa-4096 --days 3650
```

See [USAGE.md](usage.md#goca-ca) for the full `goca ca create` reference,
including creating intermediates under a root.

## Running underneath an existing CA

If you already operate a CA — pfSense, a corporate root, an offline root —
goca can run as an intermediate beneath it instead of as its own root. This
is covered in full in [README.md](index.md#running-under-a-ca-you-already-have)
and the [`goca ca request` / `goca ca import` / `goca ca import-signed`
reference](usage.md#goca-ca) in USAGE.md. Short version:

```bash
# goca generates the key and a CSR; the key never leaves this server
goca ca request --name "Branch Issuing CA" --common-name "Branch Issuing CA" --out branch.csr

# sign branch.csr with your existing authority, then bring the result back
goca ca import-signed branch-issuing-ca --cert signed.crt --chain root.crt --default
```

## Trusting the CA on clients

Once a CA exists, its certificate is served without authentication so
machines and browsers can fetch it directly:

```
http://your-server:8080/public/ca/<slug>.crt
http://your-server:8080/public/crl/<slug>.crl
```

Linux:

```bash
sudo curl -fsSL http://ca.example.com:8080/public/ca/acme-root-ca.crt \
  -o /usr/local/share/ca-certificates/acme-root-ca.crt
sudo update-ca-certificates
```

macOS:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain acme-root-ca.crt
```

Windows (PowerShell, run as Administrator):

```powershell
Invoke-WebRequest -Uri "http://ca.example.com:8080/public/ca/acme-root-ca.crt" -OutFile "acme-root-ca.crt"
Import-Certificate -FilePath "acme-root-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

## Upgrading

1. Stop the running service: `sudo systemctl stop goca-web` (or the launchd
   equivalent).
2. Back up `goca.db` and `config.yaml` together (see
   [Backup and disaster recovery](#backup-and-disaster-recovery)).
3. Replace the binary with the new build.
4. Start it again: `sudo systemctl start goca-web`, or `goca run web` in the
   foreground to watch the startup logs.

**The database migrates itself on open.** Missing tables and columns are
added in place on the first connection from the new binary; existing data
and encrypted keys are left untouched. There's no separate migration command
to run.

## Backup and disaster recovery

Back up the database together with `config.yaml` — one without the other is
useless, since `config.yaml` holds the master key that decrypts every private
key the database stores.

**SQLite:**

- `goca.db` — every CA, certificate, user, and (if retained) encrypted
  private key.
- `config.yaml` — the master key that decrypts them.

A snapshot of `goca.db` taken while the portal is running is safe: SQLite is
opened in WAL mode, so reads are consistent even mid-write. Copy the `.db`
file (and any `.db-wal` / `.db-shm` alongside it, if present) directly.

To restore: put both files back in place, matching the paths `--data-dir` /
`--out` originally used (or point `--config` at wherever you put them), and
start the portal. No explicit migration or repair step is needed.

**PostgreSQL:** back it up the way you back up any PostgreSQL database
(`pg_dump`/`pg_basebackup`, or your platform's managed snapshotting), together
with `config.yaml`. To restore, recreate the database from that backup and
point a matching `config.yaml` (same `database:` block, same `master_key`) at
it.

## Uninstalling

```bash
sudo goca uninstall web            # or --user-scope, to match how it was installed
```

Then remove the data directory (`goca.db`, `config.yaml`, and anything else
under `--data-dir`) if you want nothing left behind. There's no separate
"uninstall" for the data — it's just files on disk.

## Troubleshooting

**`no goca config found; run 'goca setup' first`** — none of the standard
locations (`--config`, `GOCA_CONFIG`, `~/.goca/config.yaml`,
`/etc/goca/config.yaml`) has a file. Run `goca setup`, or pass `--config`
pointing at wherever you put it.

**`security.master_key is missing; re-run 'goca setup'`** — the config file
exists but doesn't carry a master key, usually because it was hand-created
rather than produced by `goca setup`. Regenerate it with `goca setup`, or add
a base64-encoded 32-byte value under `security.master_key` yourself (openssl:
`openssl rand -base64 32`).

**Port already in use** — another process is bound to the configured port.
Pick a different one with `goca run web --port=...`, or find and stop the
conflicting process.

**Writing the systemd/launchd unit fails with a permissions error** —
`install web` is writing to a system directory (`/etc/systemd/system` or
`/Library/LaunchDaemons`) and needs root. Re-run under `sudo`, or add
`--user-scope` to install into your own service manager instance instead.

**LDAP login always fails** — run `goca ldap test` first to isolate
connectivity/bind/search-base problems from filter/attribute problems, then
`goca ldap login <user>` to see exactly what DN, groups, and role goca
resolved for that account.

**Lost the config file / master key** — there is no recovery path for
encrypted private keys without it. Certificates themselves (the public part)
remain in the database and readable; any key goca was asked to retain is
gone. This is why the config file and database are backed up together — see
[Backup and disaster recovery](#backup-and-disaster-recovery).
