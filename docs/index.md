# goca

A self-hosted certificate authority in a single Go binary. The CLI, the REST API
and an embedded web portal are the same program, backed by one SQLite file by
default, or PostgreSQL when you want a server-based database.

**Documentation:**
[SETUP.md](setup.md) — building, `goca setup`, running, installing as a
service, TLS, LDAP, upgrading, backups ·
[USAGE.md](usage.md) — the complete CLI reference, every command and flag ·
[ACME-EAB.md](acme-eab.md) — ACME for cert-manager and other clients, EAB-only ·
[SECRETS.md](secrets.md) — the secret manager: post-quantum envelope encryption,
key custody, and mounting secrets into Kubernetes with the CSI provider ·
this file — what goca is and does, the REST API, and how it's built.

---

## What it is

- **One binary, no runtime dependencies.** The web UI (HTML, CSS, JS) is compiled
  in with `go:embed`. The default SQLite backend is the pure-Go `modernc.org/sqlite`
  driver, and the optional PostgreSQL backend is the pure-Go `jackc/pgx` driver, so
  there is no cgo, no libc pinning and no OpenSSL to install. `GOOS=linux go build`
  produces a file you can scp anywhere.
- **SQLite or PostgreSQL.** `goca setup` defaults to a SQLite file, zero extra
  moving parts. Point it at PostgreSQL instead when you want a server-based
  database — see [SETUP.md](setup.md#database).
- **Everything in three places.** Every capability exists in the web UI, the REST
  API and the CLI, because all three call the same service layer
  ([internal/ca/service.go](https://github.com/mevijays/goca/blob/main/internal/ca/service.go)). Nothing is CLI-only or
  API-only.
- **Its own root, or someone else's.** goca can be a self-signed root CA, or run
  as an intermediate underneath a CA you already operate — pfSense, a corporate
  root, an offline root. See [Running under a CA you already have](#running-under-a-ca-you-already-have).
- **Local, LDAP, or SSO login.** Directory and OIDC accounts (Dex, Keycloak,
  Okta, Azure Entra ID, ...) appear on first sign-in and take their role from
  directory/provider groups. A local break-glass admin always works, even when
  the directory or SSO provider is down. See [LDAP and SSO](#ldap-and-sso).
- **Nothing is lost.** Every certificate ever issued stays searchable and
  re-downloadable — certificate, chain, CSR, and the private key when you asked
  goca to keep it. Private keys are AES-256-GCM encrypted at rest.
- **Full certificate lifecycle.** Issue, renew/rotate, revoke, hold/release,
  bulk-revoke by filter, retire whole authorities with cascading revocation.
- **An SSL utility open to anyone.** Decode a certificate, key or CSR - paste,
  upload, or a cert+key pair to check they match - with no account needed and
  nothing stored. See [SSL utility](#the-ssl-utility).
- **ACME for private domains.** An RFC 8555 server, External Account Binding
  only — no HTTP-01/DNS-01 challenge is ever validated, which is what makes it
  usable for internal zones cert-manager and friends could never prove
  ownership of publicly. See [ACME-EAB.md](acme-eab.md), or
  [k8s-demo/](kubernetes/cert-manager.md) for a runnable cert-manager walkthrough.
- **A secret manager, sealed with post-quantum envelope encryption.** Named,
  versioned secrets — and certificates goca itself issued, materialized fresh on
  every read — mountable straight into Kubernetes pods via a Secrets Store CSI
  Driver provider, with no plaintext ever touching etcd. See [SECRETS.md](secrets.md),
  or [k8s-demo/csi/](kubernetes/csi.md) for a runnable walkthrough.

## Quick start

```bash
go build -o goca .
./goca setup
./goca run web --port=8080
```

Open `http://localhost:8080` and sign in. For the full setup walkthrough
(unattended installs, LDAP, TLS, running as a service) see
**[SETUP.md](setup.md)**.

### Or with Docker

```bash
docker volume create goca-data

docker run --rm -it -v goca-data:/data ghcr.io/mevijays/goca:latest \
    setup --data-dir /data --out /data/config.yaml --port 8080 \
    --admin-user admin --admin-password 'S3cret!!' --with-ca --ca-common-name "Acme Root CA"

docker run -d --name goca -p 8080:8080 -v goca-data:/data ghcr.io/mevijays/goca:latest
```

The image is published from every tagged release by
[`.github/workflows/release.yml`](https://github.com/mevijays/goca/blob/main/.github/workflows/release.yml) — see the
[Dockerfile](https://github.com/mevijays/goca/blob/main/Dockerfile) for what's in it (a single static ~28 MB binary on
`distroless/static`, running as a non-root user). Build it yourself with
`docker build -t goca .`.

Or with [docker-compose.yaml](https://github.com/mevijays/goca/blob/main/docker-compose.yaml), which wires up the same
image plus an optional PostgreSQL service:

```bash
docker compose run --rm goca setup --data-dir /data --out /data/config.yaml \
    --non-interactive --admin-user admin --admin-password 'S3cret!!' \
    --base-url http://localhost:8080
docker compose up -d goca
```

See the comments at the top of that file for the PostgreSQL variant
(`docker compose --profile postgres up -d`).

---

## A tour of what it does

Full flag-by-flag reference for every command below lives in
**[USAGE.md](usage.md)**. This section is a guided overview.

### Certificate authorities

Create a self-signed root, then optionally intermediates beneath it so the root
can go offline. The CA certificate and its encrypted private key live in the
database (SQLite or PostgreSQL), and both are downloadable at any time.

```bash
goca ca create --wizard
goca ca create --name "Acme Root CA" --common-name "Acme Root CA" \
    --organization Acme --country IN --key-type rsa-4096 --days 3650
goca ca create --name "Acme Issuing CA" --common-name "Acme Issuing CA" \
    --parent acme-root-ca --days 1825 --path-len 0 --default

goca ca list
goca ca show acme-issuing-ca
goca ca export acme-root-ca --out ./ca --with-key
goca ca crl acme-issuing-ca --out acme.crl --der
```

Machines can fetch the trust anchor and the CRL without credentials:

```
http://your-server:8080/public/ca/acme-root-ca.crt
http://your-server:8080/public/crl/acme-issuing-ca.crl
```

Point `--crl-url` at that second URL when creating a CA and every certificate it
issues will carry it. See **[USAGE.md — goca ca](usage.md#goca-ca)** for every
flag.

### Running under a CA you already have

If you already operate a CA — pfSense, a corporate root, an offline root — goca
can sit underneath it as an intermediate. Three ways in, all available in the
CLI, the API and the portal (**Authorities → Connect an external CA**).

**1. Generate the request here (recommended).** goca creates the key, keeps it
encrypted, and gives you a CSR. The private key never leaves this server.

```bash
goca ca request --name "Branch Issuing CA" --common-name "Branch Issuing CA" \
    --organization Acme --key-type rsa-4096 --out branch.csr
```

Sign `branch.csr` with your authority. On pfSense: **System → Cert. Manager →
CAs → Add**, choose *Sign an intermediate Certificate Authority*, paste the
request, pick the signing CA, then export the issued certificate.

```bash
goca ca import-signed branch-issuing-ca --cert signed.crt --chain pfsense-root.crt --default
```

The signed certificate is checked against the key goca kept, so a certificate
issued for a different request is refused rather than silently stored. Anything
in `--chain` that goca doesn't already have is imported as a trust anchor, so
chains resolve all the way to the root.

**2. Import an intermediate and its key.** When your tool can export the pair
(pfSense does, under Cert. Manager → CAs → Export), goca can issue immediately:

```bash
goca ca import --cert intermediate.crt --key intermediate.key \
    --chain root.crt --name "pfSense Issuing CA" --default
```

**3. Import a trust anchor.** Certificate only. It completes chains and is
published for download, but cannot sign:

```bash
goca ca import --cert pfsense-root.crt --name "pfSense Root CA"
```

Check what's outstanding at any time:

```bash
goca ca pending                        # awaiting an external signature
goca ca pending --csr branch-issuing-ca # print the request again
goca ca list                            # kind and origin of every authority
```

```
ID  NAME                  SLUG                  KIND          ORIGIN    KEY     STATUS
1   Lab Issuing CA        lab-issuing-ca        intermediate  imported  stored  active
2   pfSense Root CA 2026  pfsense-root-ca-2026  trust anchor  imported  none    active
```

Certificates issued from an imported intermediate chain to the external root,
and verify against it with nothing of goca's in the trust path:

```bash
openssl verify -CAfile pfsense-root.crt -untrusted app-chain.pem app.crt
```

A trust anchor has no key, so goca refuses to issue or sign a CRL from it and
says why. Same for an authority still waiting on its signature. Full reference:
**[USAGE.md — goca ca](usage.md#goca-ca)**.

### Requesting certificates

Two paths, both available in all three interfaces.

**goca makes the key and CSR for you:**

```bash
goca cert issue --common-name app.internal.lan \
    --san app.internal.lan --san api.internal.lan --san 10.0.0.20 \
    --profile server --days 397 --out ./app
```

Writes `app.internal.lan.{crt,key}`, `-chain.pem` and `-fullchain.pem`. The key
is stored encrypted so you can fetch it again later. Pass `--no-store-key` for a
download-once workflow where goca keeps only the certificate.

**You bring your own CSR** (from openssl or anywhere else):

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout app.key -out app.csr \
    -subj "/CN=app.internal.lan" \
    -addext "subjectAltName=DNS:app.internal.lan,IP:10.0.0.20"

goca cert sign --csr app.csr --days 397 --cert-out app.crt
```

Your private key never leaves your machine. If you *want* goca to keep it so the
pair stays re-downloadable, add `--key app.key` — it is verified against the CSR
before being stored.

Don't have a CSR and want one without issuing anything?

```bash
goca csr new --common-name app.internal.lan --san app.internal.lan --out ./req
```

The web portal has the same three flows: a request form with a
generate-or-paste-CSR toggle, and a standalone CSR generator under **CSR tool**.
Full flags: **[USAGE.md — goca cert](usage.md#goca-cert)**,
**[goca csr](usage.md#goca-csr)**.

Just need to decode a certificate, private key or CSR someone handed you - the
`openssl x509/req/pkey -text -noout` you'd otherwise reach for a terminal for?
**SSL utility** (`/tools/ssl`) does that: paste or upload one, or a cert and
its key together to check they match. It needs no account - even a signed-out
visitor can use it - and nothing submitted to it is ever stored or logged.

### The SSL utility

`/tools/ssl` is goca's `openssl x509/req/pkey -text -noout` equivalent: paste
or upload a certificate, private key or CSR to see it decoded - subject,
issuer, SANs, validity, key usage, fingerprints, the works. Paste a
certificate and its private key together and it reports whether they actually
match, using the same comparison as `openssl x509 -noout -pubkey | openssl
pkey -pubin -outform der | sha256sum`, without you having to run it.

It's reachable without signing in (there's a link on the login page), because
there's nothing to protect: nothing submitted is stored, logged, or written
to the database, and a submitted private key's own material is never echoed
back either - only its type and a fingerprint of its public half, which is
what the match check compares.

There's a CLI equivalent for certificates and CSRs too:
**[goca inspect](usage.md#goca-inspect-file-)**.

### Finding and re-downloading, later

Everything issued is searchable by common name, SAN, serial, fingerprint or
requester, and every artefact stays available.

```bash
goca cert list
goca cert list --query internal.lan --status active
goca cert list --expiring-in 30
goca cert show 12
goca cert export 12 --out ./app --with-key
goca cert export 3A7F1C... --stdout cert
goca cert export 12 --p12 app.p12 --p12-password 'secret'
```

The portal's certificate list offers the same filters, and each detail page has
buttons for the certificate (PEM/CRT/DER), the chain, the full chain, the CSR,
the private key, a PKCS#12 bundle for browsers and mobile devices, and a ZIP of
everything with a README explaining each file.

### Renewing and rotating

A replacement carries the same subject, SANs and profile. By default it gets a
**new key** — that's the point of rotating, since it retires the old key along
with the old certificate.

```bash
goca cert renew 12                      # new key, same validity span
goca cert renew 12 --days 397 --out ./app
goca cert renew 12 --same-key           # keep the key (only if it's pinned somewhere)
goca cert renew 12 --revoke-old         # retire the predecessor as superseded
goca cert renew --expiring-in 30 --all  # rotate everything due
goca cert history 12                    # walk the rotation chain
```

The old certificate stays valid unless you pass `--revoke-old`, so you can
deploy the new one first and retire the old one after. `--same-key` keeps a
compromised key in play, which is why a fresh key is the default.

In the portal, every active certificate has a **Renew** panel, and the list has
a **Renew** bulk action. The rotation chain is shown on the detail page.

### Revocation

```bash
goca cert revoke 12 --reason keyCompromise --crl
goca ca crl acme-issuing-ca --out acme.crl --der
```

`--crl` regenerates the authority's CRL immediately. The public CRL endpoint
always serves a freshly signed list.

**Holds** are reversible. Use one while you're still investigating:

```bash
goca cert hold 12       # appears on the CRL as certificateHold
goca cert release 12    # drops off the CRL again
```

Only a hold can be lifted. Every other reason is a permanent statement about the
certificate, and goca will not undo it.

**In bulk**, by filter. At least one filter is required — an unfiltered bulk
revoke is refused, because it's rarely what anyone means:

```bash
goca cert revoke-many --ca branch-issuing-ca --reason cessationOfOperation --crl
goca cert revoke-many --query old.internal.lan --reason superseded
goca cert revoke-many --profile client --expired --yes
```

Matches are listed and confirmed first, and already-revoked certificates are
skipped rather than erroring, so the command is safe to re-run. The certificate
list in the portal has checkboxes for the same operations.

**Retiring a whole authority:**

```bash
goca ca revoke branch-issuing-ca --reason cessationOfOperation
goca ca revoke branch-issuing-ca --cascade   # + every certificate it issued
```

Issuance stops immediately. With `--cascade`, everything it issued is revoked
too, along with any subordinate authorities beneath it. When goca holds the
issuer, the retired CA's own certificate goes onto that issuer's CRL — the part
relying parties can actually observe. When it doesn't (a root, or an external
issuer), goca says so and tells you to revoke it on the other side as well.
Full reference: **[USAGE.md — goca cert](usage.md#goca-cert)**,
**[revocation reasons](usage.md#revocation-reasons)**.

### Profiles

`--profile` sets key usage and extended key usage:

| Profile | Use |
| --- | --- |
| `server` | TLS server authentication (default) |
| `client` | TLS client authentication, mutual TLS |
| `server-client` | Both |
| `code-signing` | Code signing |
| `email` | S/MIME |

A `server` certificate with no SANs gets its CN promoted to a DNS SAN, because
no modern client accepts a bare CN.

### Key types

`rsa-2048`, `rsa-3072`, `rsa-4096`, `ec-p256`, `ec-p384`, `ec-p521`, `ed25519`.
Aliases like `RSA 4096`, `p-256` and `prime256v1` are accepted everywhere.

---

## The REST API

Every endpoint lives under `/api/v1` and accepts either a portal session cookie
or a bearer token.

**Interactive reference:** sign in as an admin and open **API** in the top
navigation (`/settings/api-docs`) for a full Swagger UI browser over every
endpoint below, generated from an embedded OpenAPI 3.0 spec
([internal/web/openapi.yaml](https://github.com/mevijays/goca/blob/main/internal/web/openapi.yaml)) — including a
"Try it out" console once you paste a bearer token into its Authorize dialog.
Everything is vendored (no CDN calls), matching the portal's own strict CSP.
The raw spec is also downloadable from that page, or directly at
`/settings/api-docs/openapi.yaml` (admin session required).

```bash
goca token create ansible --role admin --days 365
```

The plaintext is shown once; only a hash is stored.

```bash
export TOK=goca_xxxxxxxx_...

curl -H "Authorization: Bearer $TOK" localhost:8080/api/v1/cas

curl -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"subject":{"common_name":"app.internal.lan"},
       "sans":["app.internal.lan","10.0.0.20"],
       "key_type":"ec-p256","profile":"server","days":397}' \
  localhost:8080/api/v1/certificates

curl -H "Authorization: Bearer $TOK" \
  localhost:8080/api/v1/certificates/12/download/bundle.zip -o bundle.zip
```

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/health` | no auth |
| `GET` | `/api/v1/me`, `/api/v1/stats` | |
| `GET` `POST` | `/api/v1/cas` | POST is admin-only |
| `GET` `DELETE` | `/api/v1/cas/{id}` | |
| `POST` | `/api/v1/cas/{id}/default`, `/status`, `/crl` | admin |
| `GET` | `/api/v1/cas/{id}/download/{file}` | `ca.crt`, `ca.pem`, `ca.der`, `ca.key`, `chain.pem`, `crl.pem`, `crl.crl`, `request.csr`, `bundle.zip` |
| `POST` | `/api/v1/cas/request` | subordinate CSR for an external authority (admin) |
| `POST` | `/api/v1/cas/import` | import a CA, with or without its key (admin) |
| `GET` | `/api/v1/cas/pending` | authorities awaiting a signature (admin) |
| `GET` | `/api/v1/cas/{id}/csr` | the stored request of a pending authority |
| `POST` | `/api/v1/cas/{id}/import-signed` | complete a pending authority (admin) |
| `POST` | `/api/v1/cas/{id}/revoke` | retire an authority, `{"cascade":true}` (admin) |
| `GET` `POST` | `/api/v1/certificates` | search / issue |
| `GET` | `/api/v1/certificates/{id\|serial}` | |
| `POST` | `/api/v1/certificates/{id}/revoke` | |
| `POST` | `/api/v1/certificates/{id}/renew` | `{"days":397,"same_key":false,"revoke_old":true}` |
| `GET` | `/api/v1/certificates/{id}/history` | the rotation chain |
| `POST` | `/api/v1/certificates/{id}/hold` · `/release` | reversible suspension |
| `POST` | `/api/v1/certificates/renew-expiring` | `{"within_days":30}` (admin) |
| `POST` | `/api/v1/certificates/bulk-revoke` | by `ids` or a filter (admin) |
| `GET` | `/api/v1/certificates/{id}/download/{file}` | `cert.pem`, `cert.der`, `key.pem`, `chain.pem`, `fullchain.pem`, `request.csr`, `bundle.p12`, `bundle.zip` |
| `POST` | `/api/v1/csr` | generate a key + CSR, stores nothing |
| `POST` | `/api/v1/inspect` | describe any PEM certificate or CSR |
| `GET` `POST` `DELETE` | `/api/v1/tokens` | |
| `GET` `POST` `PATCH` `DELETE` | `/api/v1/users` | admin |
| `GET` | `/api/v1/audit` | admin |
| `GET` `POST` | `/api/v1/acme/eab` | manage EAB credentials (admin) — see [ACME-EAB.md](acme-eab.md) |
| `GET` | `/api/v1/acme/accounts` | registered ACME accounts (admin) |

Public, unauthenticated: `/public/ca/{slug}.crt` (also `.pem`, `.der`) and
`/public/crl/{slug}.crl` (also `.pem`). Also unauthenticated at this layer,
with its own JWS-based protocol authentication instead: `/acme/*` — the ACME
server itself, see [ACME-EAB.md](acme-eab.md).

Every CLI command in [USAGE.md](usage.md) has a REST equivalent in this table
and vice versa — pick whichever fits the automation you're writing.

---

## LDAP and SSO

goca supports local password accounts, LDAP/Active Directory, and OIDC/SSO
(Dex, Keycloak, Okta, Azure Entra ID, ...), any combination at once, with a
local break-glass admin that always works even when the directory or SSO
provider is down. Both map directory/provider groups onto goca's admin/user
roles the same way. Full setup, including every flag:
**[SETUP.md — LDAP setup](setup.md#ldap-setup)**,
**[SETUP.md — Single sign-on (OIDC) setup](setup.md#single-sign-on-oidc-setup)**.

```bash
goca ldap test
goca ldap login alice          # full login, shows groups and the resulting role
```

OIDC has no CLI equivalent to `ldap test`/`ldap login` - verify it by
actually signing in: open the portal and click **Sign in with SSO**.

## Roles

| | user | admin |
| --- | --- | --- |
| Request certificates | yes | yes |
| See certificates | own only | all |
| Download a stored key | own only | all |
| Create/delete authorities | no | yes |
| Download a CA private key | no | yes |
| Manage users and view the audit log | no | yes |

The portal refuses to remove or demote the last enabled admin.

## Configuration

`goca setup` writes `config.yaml`, and every runtime setting — server address,
auth mode, certificate defaults, LDAP, OIDC — lives there. Full schema,
discovery order, and the master-key backup story:
**[SETUP.md — the config file](setup.md#the-config-file)**.

## Trusting the CA on clients

**[SETUP.md — trusting the CA on clients](setup.md#trusting-the-ca-on-clients)**
covers Linux, macOS and Windows. Quick reference:

```bash
sudo curl -fsSL http://ca.example.com:8080/public/ca/acme-root-ca.crt \
  -o /usr/local/share/ca-certificates/acme-root-ca.crt
sudo update-ca-certificates
```

nginx, using the exported files:

```nginx
ssl_certificate     /etc/nginx/certs/app.internal.lan-fullchain.pem;
ssl_certificate_key /etc/nginx/certs/app.internal.lan.key;
```

---

## Security notes

- Private keys (CA and end-entity) are encrypted with AES-256-GCM under the
  config's master key. Nothing sensitive is stored in cleartext in the database.
- Session and API tokens are stored as SHA-256 hashes; passwords as bcrypt.
- Serial numbers are 128 bits of `crypto/rand`.
- All state-changing form posts require a CSRF token; session-authenticated API
  calls do too. Bearer-token calls are exempt, as they cannot be driven from a
  browser.
- The portal sets `X-Content-Type-Options`, `X-Frame-Options`, a strict
  `Content-Security-Policy` that permits no external origins, and `no-store` on
  every download.
- Key downloads, CA key exports and failed logins are all written to the audit
  log with the actor and source address.
- goca refuses to issue a certificate that outlives its issuing CA.
- An imported certificate must be a real CA (`CA:TRUE`, `keyCertSign`) and, when
  a key is supplied, must match it. A certificate signed for a different request
  cannot activate a pending authority.
- A trust anchor (no private key) and an authority awaiting its signature can
  never become the default issuer, nor sign a certificate or a CRL.
- Renewal defaults to a fresh key, so rotating retires the old key too.

## Upgrading

The database migrates itself on open: missing columns and tables are added in
place, and existing data is left alone. Back up `goca.db` and `config.yaml`
together before upgrading, as always — the master key in the config is what
decrypts the keys in the database. Full procedure:
**[SETUP.md — upgrading](setup.md#upgrading)**.

## Development

```bash
go test ./...
go build -o goca .
GOOS=linux GOARCH=amd64 go build -o goca-linux-amd64 .
```

| Package | Responsibility |
| --- | --- |
| `internal/pki` | keys, CSRs, CA creation, signing, CRLs — standard library crypto only |
| `internal/store` | Schema and queries — SQLite by default, PostgreSQL optional |
| `internal/secret` | AES-GCM encryption for keys at rest |
| `internal/ca` | the service layer the CLI, API and portal all call |
| `internal/auth` | local and LDAP authentication, sessions, API tokens |
| `internal/ldapauth` | directory binding, search and group mapping |
| `internal/web` | portal handlers, REST API, embedded templates and assets |
| `internal/cli` | cobra commands |
| `internal/service` | systemd and launchd unit generation |
| `internal/acme` | RFC 8555 ACME server (EAB-only) — see [ACME-EAB.md](acme-eab.md) |
| `internal/pqcrypt` | hybrid ML-KEM-768 + X25519 envelope encryption — see [SECRETS.md](secrets.md) |
| `internal/vault` | secret manager service layer (versioning, bindings, cert materialization) |
| `internal/k8sauth` | verifies Kubernetes ServiceAccount tokens (OIDC/JWKS + TokenReview) |
| `internal/csi` | Secrets Store CSI Driver provider — `goca run csi-provider` |

Vendored, not written here: [Swagger UI](https://github.com/swagger-api/swagger-ui)
(Apache 2.0, license kept alongside it at `internal/web/static/swagger/LICENSE`),
serving the interactive API docs at `/settings/api-docs`; the CSI provider's gRPC
stubs in `internal/csi/v1alpha1`, generated from
[kubernetes-sigs/secrets-store-csi-driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver)'s
own `.proto` (Apache 2.0, attribution kept in each generated file).
