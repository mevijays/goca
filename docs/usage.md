# goca CLI reference

Complete reference for the `goca` command line: every command, every flag,
every default. For getting a server running in the first place, see
[SETUP.md](setup.md). For an overview of what goca does, see
[README.md](index.md).

Everything the CLI does is also available in the REST API and the web
portal — they call the same service layer, so nothing here is CLI-only
capability. The `README.md` [API table](index.md#the-rest-api) maps CLI
commands to their `/api/v1` equivalents.

!!! tip "Administering goca from another machine"
    `goca` talks to the database directly, so it has to run **on the server
    host** and needs the master key. To manage a goca server over the network
    — from a laptop, a CI job or a container — use
    [`gocactl`](gocactl.md), the remote client. It signs in with your own
    account, is limited to what your role allows, and renders the same output
    as the commands below.

## Contents

- [Global flags and conventions](#global-flags-and-conventions)
- [`goca setup`](#goca-setup)
- [`goca run web`](#goca-run-web)
- [`goca install web`](#goca-install-web)
- [`goca uninstall web`](#goca-uninstall-web)
- [`goca ca`](#goca-ca) — authorities, including external-CA integration
- [`goca cert`](#goca-cert) — issuance, lifecycle, revocation
- [`goca csr`](#goca-csr)
- [`goca inspect`](#goca-inspect-file-)
- [`goca user`](#goca-user)
- [`goca token`](#goca-token)
- [`goca ldap`](#goca-ldap)
- [`goca acme`](#goca-acme) — ACME (RFC 8555) EAB credentials and accounts
- [`goca version`](#goca-version)
- [Key types](#key-types)
- [Certificate profiles](#certificate-profiles)
- [Revocation reasons](#revocation-reasons)
- [Referring to a CA or a certificate](#referring-to-a-ca-or-a-certificate)
- [Reading and writing PEM: stdin/stdout conventions](#reading-and-writing-pem-stdinstdout-conventions)
- [Scripting with --json](#scripting-with-json)
- [Exit codes](#exit-codes)

---

## Global flags and conventions

These apply to every subcommand, and must come before or after the
subcommand's own flags (cobra accepts either):

| Flag | Default | Meaning |
| --- | --- | --- |
| `-c, --config` | *(auto-discovered)* | path to `config.yaml` — see [config discovery](setup.md#the-config-file) |
| `--json` | off | emit JSON instead of a formatted table/summary |
| `-v, --verbose` | off | verbose logging to stderr |
| `--actor` | *(current OS user)* | name recorded in the audit log for this invocation |

**`--json`** works on nearly every command — reads return the same structures
the REST API returns, and most writes echo back what was created or changed.
This makes the CLI usable from scripts without going through the HTTP API at
all. See [Scripting with --json](#scripting-with-json).

**`--actor`** defaults to `$SUDO_USER` (if running under sudo) or `$USER`,
suffixed with `(cli)`, e.g. `vijay (cli)`. Override it when running goca from
automation and you want the audit log to say something more specific, e.g.
`--actor "ansible-deploy"`.

**Interactive prompts:** most creation commands accept a `--wizard` flag that
prompts for every field, and fall into the same prompts automatically when a
required field is omitted and stdin is a terminal. Piped/scripted invocations
(stdin not a terminal, or explicit `--non-interactive` where supported) never
prompt — missing required values are an error instead.

**Confirmation:** destructive operations (delete, bulk revoke, retiring a CA)
ask for interactive confirmation unless `--yes` is passed, and refuse to run
at all non-interactively without `--yes`.

---

## `goca setup`

Generates the config file, master/session keys, database, and admin account.
Full reference, including every flag, is in
[SETUP.md](setup.md#unattended-setup) since it's fundamentally a setup-time
operation, not a day-to-day one.

```bash
goca setup                      # interactive wizard
goca setup --non-interactive --admin-user admin --admin-password 'S3cret!!' --port 8080
```

---

## `goca run web`

Serves the portal and REST API in the foreground.

```
goca run web [flags]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--port` | config file's `server.port` | port to listen on (overrides the config file for this run) |
| `--listen` | config file's `server.listen` | address to bind |
| `--tls-cert` | — | serve HTTPS with this certificate |
| `--tls-key` | — | private key for `--tls-cert` |

Runs until `SIGINT`/`SIGTERM`, then shuts down gracefully. See
[SETUP.md](setup.md#running-the-portal) and
[SETUP.md — TLS](setup.md#tls).

---

## `goca install web`

Generates and (optionally) enables a systemd (Linux) or launchd (macOS) unit
that runs the current binary as `run web`.

```
goca install web [flags]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--port` | the configured port | port the service listens on |
| `--listen` | — | address the service binds to |
| `--user` | current user | unix user to run as |
| `--binary` | this executable's path | path to the goca binary |
| `--name` | `goca-web` | service unit name |
| `--user-scope` | off | install into the current user's service manager, not the system one |
| `--now` | off | reload the manager, then enable and start the service |
| `--print` | off | print the unit file instead of installing it |
| `--tls-cert` / `--tls-key` | — | serve HTTPS with this certificate |

Full walkthrough, including permission requirements: [SETUP.md](setup.md#installing-as-a-service).

## `goca uninstall web`

Stops, disables, and removes an installed unit.

```
goca uninstall web [--name goca-web] [--user-scope]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--name` | `goca-web` | service unit name |
| `--user-scope` | off | remove from the current user's service manager |

---

## `goca ca`

Manage certificate authorities: create, list, inspect, export, retire, and —
the newer capability — connect goca to a CA you already operate elsewhere
(pfSense, a corporate root, an offline root).

Alias: `goca authority`.

### `goca ca create`

Create a root or intermediate CA. Without `--parent` it's a self-signed root;
with `--parent` it's signed by an existing authority in this goca instance.

```
goca ca create [flags]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--wizard` | off | prompt for every field |
| `--name` | the common name | display name |
| `--common-name` | — | subject common name (CN) |
| `--organization` | — | subject organization (O) |
| `--organizational-unit` | — | subject organizational unit (OU) |
| `--country` | — | subject country code (C) |
| `--province` | — | subject state/province (ST) |
| `--locality` | — | subject locality (L) |
| `--key-type` | config default | see [key types](#key-types) |
| `--days` | config's `default_ca_days` | validity in days |
| `--parent` | — | id, slug, or name of the signing authority (blank = self-signed root) |
| `--path-len` | `1` | how many CA levels may sit below this one |
| `--crl-url` | — | CRL distribution point to embed in issued certificates (repeatable) |
| `--ocsp-url` | — | OCSP responder URL to embed in issued certificates (repeatable) |
| `--permitted-dns` | — | restrict this CA to these DNS domains, a name constraint (repeatable) |
| `--default` | off | make this the default issuing authority |
| `--export` | — | also write the certificate, chain, and key to this directory |

```bash
goca ca create --wizard

goca ca create --name "Acme Root CA" --common-name "Acme Root CA" \
    --organization Acme --country IN --key-type rsa-4096 --days 3650

goca ca create --name "Acme Issuing CA" --common-name "Acme Issuing CA" \
    --parent acme-root-ca --days 1825 --path-len 0 --default
```

### `goca ca list`

List every authority: id, name, slug, kind (root/intermediate/trust anchor),
origin (goca/imported), key state, expiry, status, default flag. Alias: `ls`.

```
goca ca list
```

### `goca ca show <id|slug|name>`

Full detail on one authority: subject, serial, key type, signature algorithm,
validity, key usage, CRL/OCSP URLs, certificates issued/revoked counts.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--pem` | off | also print the certificate PEM |

```bash
goca ca show acme-issuing-ca
goca ca show acme-issuing-ca --pem
```

### `goca ca export <id|slug|name>`

Write a CA's certificate, chain, CRL, and (optionally) its private key to
disk — or print a single artefact to stdout.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --out` | current directory | directory to write files into |
| `--with-key` | off | also export the CA private key (mode `0600`) |
| `--stdout` | — | print one artefact instead: `cert`, `chain`, `key`, or `crl` |

```bash
goca ca export acme-root-ca --out ./ca --with-key
goca ca export acme-root-ca --stdout cert
goca ca export acme-root-ca --stdout crl > acme.crl
```

### `goca ca default <id|slug|name>`

Set the default issuing authority — the one used when a certificate request
doesn't name a CA explicitly.

```bash
goca ca default acme-issuing-ca
```

### `goca ca status <id|slug|name> <active|disabled>`

Enable or disable issuance from an authority without touching anything it
has already issued.

```bash
goca ca status acme-issuing-ca disabled
```

### `goca ca delete <id|slug|name>`

Permanently delete an authority **and every certificate it issued**,
including stored keys. This is irreversible — for retiring a CA while
keeping its history, use [`goca ca revoke`](#goca-ca-revoke-idslugname)
instead.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--yes` | off | do not ask for confirmation |

Alias: `rm`. Asks for confirmation unless `--yes`; refuses to run
non-interactively without it.

### `goca ca crl <id|slug|name>`

Generate a certificate revocation list.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --out` | stdout | write to this file instead of stdout |
| `--der` | off (PEM) | emit DER instead of PEM |

```bash
goca ca crl acme-root-ca
goca ca crl acme-root-ca --out acme.crl --der
```

### Running under a CA you already have

goca can sit underneath an authority it doesn't own — a pfSense CA, a
corporate root, an offline root — as an intermediate. Three ways in:

#### `goca ca request` — generate a subordinate CA request here (recommended)

goca creates the key pair and keeps it encrypted; only the CSR leaves this
server. Aliases: `csr`, `subordinate`.

```
goca ca request [flags]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--wizard` | off | prompt for every field |
| `--name` | the common name | display name |
| `--common-name` | — | subject common name (CN) |
| `--organization` | — | subject organization (O) |
| `--organizational-unit` | — | subject organizational unit (OU) |
| `--country` | — | subject country code (C) |
| `--province` | — | subject state/province (ST) |
| `--locality` | — | subject locality (L) |
| `--key-type` | config default | see [key types](#key-types) |
| `--parent` | — | trust anchor this will chain to, if already imported |
| `-o, --out` | stdout | write the CSR to this file instead of stdout |

```bash
goca ca request --name "Branch Issuing CA" --common-name "Branch Issuing CA" \
    --organization Acme --key-type rsa-4096 --out branch.csr
```

This creates a **pending** authority. It cannot issue anything, and never
becomes the default, until you complete it.

#### `goca ca import-signed <id|slug|name>` — bring the signed certificate back

Completes a pending authority created with `goca ca request`. Alias:
`complete`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--cert` | *(required)* | the signed CA certificate (PEM), or `-` for stdin |
| `--chain` | — | the external authority's certificate chain (PEM) |
| `--default` | off | make this the default issuing authority |

```bash
goca ca import-signed branch-issuing-ca --cert signed.crt --chain pfsense-root.crt --default
```

The signed certificate is checked against the private key goca kept — a
certificate issued for a different request is refused. Anything in `--chain`
not already known to goca is imported as a trust anchor, so the chain
resolves all the way to a root.

#### `goca ca import` — import an existing CA, with or without its key

For an intermediate you already created elsewhere and can export as a pair
(pfSense supports this under Cert. Manager → CAs → Export), or for importing
just a root as a trust anchor.

```
goca ca import [flags]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--cert` | *(required)* | CA certificate, PEM or DER, or `-` for stdin |
| `--key` | — | its private key; supply it to issue from this CA |
| `--chain` | — | issuer chain to import alongside, as trust anchors |
| `--name` | the certificate's CN | display name |
| `--default` | off | make this the default issuing authority |

```bash
# an intermediate, with its key — can issue immediately
goca ca import --cert intermediate.crt --key intermediate.key \
    --chain root.crt --name "pfSense Issuing CA" --default

# just a root — a trust anchor, cannot sign but completes chains
goca ca import --cert pfsense-root.crt --name "pfSense Root CA"
```

Without `--key`, the authority becomes a **trust anchor**: it completes
chains and is downloadable, but goca cannot use it to sign anything, and it
can never become the default issuer.

#### `goca ca pending`

List subordinate CAs still waiting on an external signature.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--csr` | — | print the stored CSR of one pending authority (by id or slug) |

```bash
goca ca pending
goca ca pending --csr branch-issuing-ca
```

### `goca ca revoke <id|slug|name>`

Retire an authority: issuance is disabled immediately, and optionally
everything it ever issued is revoked too.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--reason` | `cessationOfOperation` | RFC 5280 revocation reason — see [reasons](#revocation-reasons) |
| `--cascade` | off | also revoke every certificate issued by it, and any subordinate authorities beneath it |
| `--yes` | off | do not ask for confirmation |

```bash
goca ca revoke branch-issuing-ca --reason cessationOfOperation
goca ca revoke branch-issuing-ca --cascade --reason keyCompromise --yes
```

When goca controls this CA's issuer, the retired CA's own certificate is
added to that issuer's CRL — the part relying parties can actually observe.
For a root, or an issuer goca doesn't hold (an external one), it says so and
you need to revoke it on the other side as well.

---

## `goca cert`

Issue, search, export, and manage the lifecycle of certificates. Aliases:
`certificate`, `certs`.

### `goca cert issue`

The common case: goca generates the key, builds the CSR, and signs it in one
step. Aliases: `request`, `new`.

```
goca cert issue [flags]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--ca` | the default authority | issuing authority id, slug, or name |
| `--common-name` | — | subject common name (CN) |
| `--organization` | — | subject organization (O) |
| `--organizational-unit` | — | subject organizational unit (OU) |
| `--country` | — | subject country code (C) |
| `--province` | — | subject state/province (ST) |
| `--locality` | — | subject locality (L) |
| `--san` | — | subject alternative name (repeatable); bare values auto-typed, or prefix `DNS:`, `IP:`, `EMAIL:`, `URI:` |
| `--profile` | `server` | see [profiles](#certificate-profiles) |
| `--key-type` | config default | see [key types](#key-types) |
| `--days` | config's `default_cert_days` | validity in days |
| `--note` | — | free-text note stored with the certificate |
| `--no-store-key` | off (key is stored) | do not keep the private key in the database — it's printed once and then unrecoverable |
| `--out` | — | write cert, key, and chain into this directory |
| `--cert-out` | — | write only the certificate to this file |
| `--key-out` | — | write only the private key to this file |
| `--chain-out` | — | write only the CA chain to this file |
| `--wizard` | off | prompt for every field |

```bash
goca cert issue --wizard

goca cert issue --common-name app.internal.lan \
    --san app.internal.lan --san api.internal.lan --san 10.0.0.20 \
    --days 397 --out ./app

goca cert issue --ca acme-issuing-ca --profile client \
    --common-name "alice@example.com" --san alice@example.com
```

### `goca cert sign`

Sign a CSR you already have — from `openssl req`, or anywhere else. Your
private key stays where it was generated unless you pass `--key`.

```
goca cert sign [flags]
```

Shares all the subject/SAN/profile/days/out flags from `goca cert issue`
(everything except `--key-type`, since the CSR's own key is used), plus:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--csr` | *(required)* | CSR file in PEM format, or `-` for stdin |
| `--key` | — | the CSR's private key — supply it to have goca store the pair for later re-download |

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout app.key -out app.csr \
    -subj "/CN=app.internal.lan" \
    -addext "subjectAltName=DNS:app.internal.lan,IP:10.0.0.20"

goca cert sign --csr app.csr --days 397 --cert-out app.crt
goca cert sign --csr app.csr --key app.key --out ./app
cat app.csr | goca cert sign --csr - --profile client
```

Subject and SAN flags, when given, override what the CSR carries — useful for
correcting a request without asking for a new one.

### `goca cert list`

Search everything ever issued. Aliases: `ls`, `search`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-q, --query` | — | free-text search: common name, subject, SANs, serial, fingerprint, requester |
| `--ca` | — | limit to one authority |
| `--status` | — | `active`, `expired`, or `revoked` |
| `--profile` | — | limit to one profile |
| `--requested-by` | — | limit to one requester |
| `--expiring-in` | — | only certificates expiring within N days |
| `--limit` | `50` | maximum rows |
| `--offset` | `0` | rows to skip |
| `--sort` | `created_at` | `created_at`, `not_after`, `common_name`, or `serial` |

```bash
goca cert list
goca cert list --query internal.lan --status active
goca cert list --expiring-in 30
goca cert list --ca acme-issuing-ca --profile client --json
```

### `goca cert show <id|serial>`

Full detail on one certificate: subject, SANs, serial, authority, profile,
key usage, validity, fingerprint, note, revocation info if applicable.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--pem` | off | also print the certificate PEM |

### `goca cert export <id|serial>`

Re-download anything goca holds for a certificate — the certificate, its
chain, its CSR (if stored), and its private key (only if it was retained at
issuance).

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --out` | current directory | directory to write files into |
| `--with-key` | off | also export the private key (mode `0600`) |
| `--stdout` | — | print one artefact: `cert`, `key`, `chain`, `fullchain`, or `csr` |
| `--p12` | — | write a PKCS#12 bundle to this file |
| `--p12-password` | — | password for the PKCS#12 bundle |

```bash
goca cert export 12 --out ./app --with-key
goca cert export 3A7F1C... --stdout cert
goca cert export 12 --p12 app.p12 --p12-password 'secret'
```

### `goca cert revoke <id|serial>`

Permanently revoke a certificate.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--reason` | `unspecified` | RFC 5280 reason — see [reasons](#revocation-reasons) |
| `--crl` | off | regenerate the authority's CRL immediately |

```bash
goca cert revoke 12 --reason keyCompromise --crl
```

Without `--crl`, the certificate is revoked but the CRL isn't republished
until you run `goca ca crl` — useful if you're batching several revocations
before publishing once.

### `goca cert delete <id|serial>`

Delete the certificate **record** entirely, including any stored key. This
does **not** revoke it — a deleted certificate can no longer appear on a
CRL, so it can still be presented and accepted by relying parties. Revoke
first unless you're cleaning up a mistake. Alias: `rm`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--yes` | off | do not ask for confirmation |

### `goca cert renew [id|serial]`

Rotate a certificate: issue a replacement with the same subject, SANs, and
profile. A new key is generated by default — that's the point of rotating,
since it retires the old key along with the old certificate. Aliases:
`reissue`, `rotate`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--days` | same span as the original | validity of the replacement |
| `--same-key` | off (new key) | reuse the existing private key instead of generating one |
| `--ca` | the original issuer (if it can still sign), else the default | issue the replacement from a different authority |
| `--key-type` | the original's key type | key type for the new key (ignored with `--same-key`) |
| `--revoke-old` | off | revoke the previous certificate as superseded once the replacement exists |
| `--note` | — | note to store with the replacement |
| `--out` | — | write the new certificate, key, and chain into this directory |
| `--expiring-in` | — | batch mode: renew everything expiring within N days |
| `--all` | off | batch mode: renew every match |
| `--yes` | off | do not ask for confirmation in batch mode |

```bash
goca cert renew 12
goca cert renew 12 --days 397 --revoke-old --out ./app
goca cert renew 3A7F1C... --same-key
goca cert renew --expiring-in 30 --all --yes
```

`--same-key` keeps a potentially compromised key in play — only use it when
the key is genuinely pinned somewhere (a hardware token, a client that
verifies key continuity). The old certificate stays valid unless
`--revoke-old` is passed, so you can deploy the replacement first.

### `goca cert history <id|serial>`

Walk the renewal chain a certificate belongs to — every predecessor and
successor from a chain of `renew` calls.

```bash
goca cert history 12
```

### `goca cert hold <id|serial>`

Suspend a certificate **reversibly** (RFC 5280 `certificateHold`). It
appears on the CRL exactly like a revocation, but can be undone.

```bash
goca cert hold 12
```

Use this when you suspect a problem but haven't confirmed it. Once
confirmed, revoke properly instead — that cannot be walked back.

### `goca cert release <id|serial>`

Lift a hold, returning the certificate to active use. Alias: `unhold`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--crl` | off | regenerate the authority's CRL immediately |

Only a certificate currently on hold can be released — every other
revocation reason is permanent and goca refuses to undo it.

### `goca cert revoke-many`

Revoke every certificate matching a filter, in one operation. At least one
filter is required — an unfiltered call is refused, since "revoke
everything" is rarely what's meant.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--reason` | `unspecified` | RFC 5280 reason |
| `--ca` | — | limit to one authority |
| `-q, --query` | — | free-text match on name, SAN, serial, or requester |
| `--status` | — | limit to active, expired, or revoked |
| `--profile` | — | limit to one profile |
| `--expired` | off | limit to already-expired certificates |
| `--yes` | off | do not ask for confirmation |
| `--crl` | off | regenerate affected CRLs immediately |

```bash
goca cert revoke-many --ca branch-issuing-ca --reason cessationOfOperation --crl
goca cert revoke-many --query old.internal.lan --reason superseded
goca cert revoke-many --profile client --expired --yes
```

Matches are listed and confirmed before anything happens. Already-revoked
certificates are skipped rather than treated as errors, so the command is
safe to re-run.

---

## `goca csr`

### `goca csr new`

Create a private key and CSR without signing anything — the key is
generated and printed/written, but never stored by goca. Sign it later with
`goca cert sign`, the portal, the API, or an entirely different CA.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--common-name` | — | subject common name (CN) |
| `--organization` | — | subject organization (O) |
| `--organizational-unit` | — | subject organizational unit (OU) |
| `--country` | — | subject country code (C) |
| `--province` | — | subject state/province (ST) |
| `--locality` | — | subject locality (L) |
| `--san` | — | subject alternative name (repeatable) |
| `--key-type` | config default | see [key types](#key-types) |
| `--out` | — | directory to write the key and CSR into |
| `--csr-out` | — | write only the CSR to this file |
| `--key-out` | — | write only the private key to this file |
| `--wizard` | off | prompt for every field |

```bash
goca csr new --common-name app.internal.lan --san app.internal.lan --out ./req
```

---

## `goca inspect <file|->`

Parse and describe a PEM certificate or CSR — any PEM, not only files goca
produced. Reads from a path, or `-` for stdin.

```bash
goca inspect server.crt
goca inspect app.csr
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | goca inspect -
```

The web portal has a fuller equivalent at `/tools/ssl` (the **SSL utility**
nav tab) that also handles private keys and checks whether a pasted
certificate and key match. It needs no account — see
[README.md — The SSL utility](index.md#the-ssl-utility).

---

## `goca user`

Manage portal accounts (local, password-based; LDAP accounts appear
automatically on first sign-in and aren't managed here).

### `goca user add <username>`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--password` | prompted, or generated if non-interactive | account password |
| `--display-name` | — | display name |
| `--email` | — | email address |
| `--role` | `user` | `user` or `admin` |

### `goca user list`

List every account: id, username, name, email, source (local/ldap), role,
enabled/disabled state, last login. Alias: `ls`.

### `goca user role <username> <user|admin>`

Change a user's role.

### `goca user passwd <username>`

Set a local account's password.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--password` | prompted | new password |

### `goca user disable <username>`

Disable an account (or re-enable one).

| Flag | Default | Meaning |
| --- | --- | --- |
| `--enable` | off | re-enable instead of disabling |

### `goca user delete <username>`

Delete a portal account. Alias: `rm`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--yes` | off | do not ask for confirmation |

The portal (and the API) refuse to remove or demote the last enabled admin;
this CLI-level command has no such guard, so be careful deleting the last
admin from a script.

---

## `goca token`

Manage REST API bearer tokens.

### `goca token create <name>`

The plaintext token is printed once — only its hash is stored, so it can't
be recovered later. Mint a new one if it's lost.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--owner` | the local administrator | account that owns the token |
| `--role` | the owner's role | `user` or `admin` — capped at the owner's own role |
| `--days` | `365` | lifetime in days; `0` means never expires |

```bash
goca token create ansible --role admin --days 365
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/cas
```

### `goca token list`

List every token: id, name, prefix, owner, role, expiry, last used, state.
Alias: `ls`.

### `goca token revoke <id>`

Revoke a token immediately.

---

## `goca ldap`

### `goca ldap test`

Check connectivity, the service bind, and the search base.

```bash
goca ldap test
```

### `goca ldap login <username>`

Perform a full login against the configured directory and show the
resulting identity — DN, display name, email, groups, and whether it would
resolve to the admin role.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--password` | prompted | password to authenticate with |

```bash
goca ldap login alice
```

---

## `goca acme`

Manages ACME (RFC 8555) access. goca's ACME server is **External Account
Binding only** — there is no HTTP-01/DNS-01 challenge validation, so this
subtree is entirely about creating and inspecting the EAB credentials that
are the whole trust decision. The protocol itself (what cert-manager or any
other ACME client actually talks to) is served at `/acme/*` by `goca run
web` — there's no CLI equivalent for issuing through ACME, since that's the
client's job, not an operator's. Full walkthrough, including a cert-manager
`ClusterIssuer` example: **[ACME-EAB.md](acme-eab.md)**.

### `goca acme eab create <name>`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--ca` | the default issuing CA, resolved per order | authority accounts bootstrapped with this credential issue from |
| `--profile` | `server` | certificate profile for accounts using this credential |
| `--days` | the CA/global default | certificate validity in days |
| `--allowed-domain` | — | glob pattern an order's identifiers must match (repeatable); default: unrestricted |
| `--max-accounts` | `0` (unlimited) | cap on accounts bootstrapped with this credential |
| `--expires-in-days` | `0` (never) | disable this credential automatically after N days |

Prints the credential's `keyID` and its HMAC key. The key is shown once —
only its encrypted form is stored.

```bash
goca acme eab create cluster-a --ca acme-issuing-ca \
    --allowed-domain '*.svc.cluster-a.internal' --max-accounts 1
```

### `goca acme eab list`

Table of every credential: name, key ID, authority, profile, domains,
account usage, state. Alias: `ls`.

### `goca acme eab show <id|key-id|name>`

Full detail on one credential. Resolves by numeric id, key ID, or display
name when the name is unambiguous.

### `goca acme eab disable <id|key-id|name>`

Stops the credential bootstrapping *new* accounts. Accounts it already
created keep working — from registration onward they authenticate with
their own key, not the EAB secret.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--enable` | off | re-enable instead of disabling |

### `goca acme eab delete <id|key-id|name>`

Deletes a credential. Refuses while any ACME account was bootstrapped with
it — disable it instead, or remove those accounts first. Alias: `rm`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--yes` | off | do not ask for confirmation |

### `goca acme accounts list`

Every registered ACME account: which EAB credential bootstrapped it,
contact, status, registration and last-used times. Alias: `ls`.

### `goca acme accounts show <id>`

One account's detail plus its order history (identifiers requested,
resulting certificate id, status).

### `goca acme status`

Quick summary: the directory URL to give cert-manager, and counts of
credentials and registered accounts.

```bash
goca acme status
```

---

## `goca version`

Print the build version (respects `--json`).

---

## Key types

Accepted everywhere a `--key-type` flag appears (CA creation, certificate
issuance, CSR generation):

| Value | Notes |
| --- | --- |
| `rsa-2048` | default for issued certificates |
| `rsa-3072` | |
| `rsa-4096` | commonly used for root/intermediate CAs |
| `ec-p256` | fast, small — a good default for leaf certificates |
| `ec-p384` | |
| `ec-p521` | |
| `ed25519` | |

Aliases are accepted too: `RSA 4096`, `p-256`, `prime256v1`, `secp384r1`, and
similar variants all normalize to the canonical form above.

## Certificate profiles

`--profile` sets key usage and extended key usage on an issued certificate:

| Profile | Use |
| --- | --- |
| `server` | TLS server authentication (default) |
| `client` | TLS client authentication, mutual TLS |
| `server-client` | both |
| `code-signing` | code signing |
| `email` | S/MIME |

A `server` (or `server-client`) certificate issued with no explicit SANs
gets its CN promoted to a DNS SAN automatically, since no modern TLS client
accepts a bare CN as a hostname.

## Revocation reasons

Accepted by `--reason` on any revoke command, by name (case-insensitive) or
numeric RFC 5280 code:

| Name | Code |
| --- | --- |
| `unspecified` | 0 |
| `keyCompromise` | 1 |
| `caCompromise` | 2 |
| `affiliationChanged` | 3 |
| `superseded` | 4 |
| `cessationOfOperation` | 5 |
| `certificateHold` | 6 |
| `privilegeWithdrawn` | 9 |
| `aaCompromise` | 10 |

`certificateHold` is what `goca cert hold` uses under the hood — it's the
only reason that can later be lifted with `goca cert release`. Every other
reason is permanent.

## Referring to a CA or a certificate

Anywhere a command takes `<id|slug|name>` for a CA, all three work
interchangeably: the numeric database id, the URL-safe slug (derived from
the name, e.g. `Acme Root CA` → `acme-root-ca`), or the exact display name.

Anywhere a command takes `<id|serial>` for a certificate, either the numeric
id or the certificate's hex serial number works, including a serial with or
without colon separators.

## Reading and writing PEM: stdin/stdout conventions

Every flag that takes a file (`--cert`, `--key`, `--csr`, `--chain`, and
`goca inspect`'s positional argument) accepts `-` to mean stdin:

```bash
cat app.csr | goca cert sign --csr - --profile client
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | goca inspect -
```

Commands with a `--stdout` flag (`goca ca export`, `goca cert export`) print
a single named artefact to stdout instead of writing files, which composes
with shell redirection:

```bash
goca ca export acme-root-ca --stdout crl > acme.crl
goca cert export 12 --stdout key > app.key
```

Commands without an explicit `-o`/`--out`/`--stdout` (like `goca ca crl`
when `-o` is omitted) default to printing to stdout.

## Scripting with `--json`

Every list/show command and most write commands accept `--json`, returning
the same shapes the REST API returns — a certificate object has the same
fields whether it came from `goca cert show 12 --json` or
`GET /api/v1/certificates/12`. This makes the CLI a complete alternative to
the API for automation that already has a shell but not an HTTP client:

```bash
goca cert list --status active --json | jq '.[] | .common_name'

SERIAL=$(goca cert issue --common-name svc.internal.lan --json | jq -r '.certificate.serial')

goca ca list --json | jq -r '.[] | select(.status=="pending") | .slug'
```

## Exit codes

`0` on success. Non-zero on any error, with the error message printed to
stderr — including validation failures, refused confirmations passed
non-interactively without `--yes`, and lookups that don't resolve. There's
no separate taxonomy of exit codes beyond zero/non-zero; check the message
text if a script needs to distinguish failure reasons.
