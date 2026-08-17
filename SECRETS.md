# Secret manager

goca's secret manager stores named, versioned secrets — passwords, API keys, files,
and certificates goca itself issues — sealed at rest with a hybrid post-quantum
envelope, and readable by Kubernetes workloads through a Secrets Store CSI Driver
provider with no Kubernetes `Secret` object ever holding the plaintext.

This document covers the design, the honest story on what "post-quantum" actually
buys here, day-to-day usage across the CLI/web/API, key custody and rotation, and
the Kubernetes walkthrough. For the CSI provider specifically, see
[k8s-demo/csi/README.md](k8s-demo/csi/README.md) for copy-pasteable manifests.

## Contents

- [How it works](#how-it-works)
- [What "post-quantum" actually buys here](#what-post-quantum-actually-buys-here)
- [Quick start](#quick-start)
- [Secret types](#secret-types)
- [Versions](#versions)
- [Managing secrets: CLI, web portal, REST API](#managing-secrets-cli-web-portal-rest-api)
- [Kubernetes: mounting secrets with the CSI provider](#kubernetes-mounting-secrets-with-the-csi-provider)
- [Key custody and what compromise means](#key-custody-and-what-compromise-means)
- [Rotation](#rotation)
- [Threat model and limitations](#threat-model-and-limitations)
- [Troubleshooting](#troubleshooting)
- [Reference: envelope format and schema](#reference-envelope-format-and-schema)

## How it works

```
  CLI / web portal / REST API  ──┐
                                  ├──>  internal/vault  ──>  internal/pqcrypt  ──>  store
  goca run csi-provider (k8s)  ──┘        (Service)          (Seal / Open)      (SQLite/Postgres)
```

Every secret is a named row (`secrets`) with zero or more immutable versions
(`secret_versions`) and zero or more Kubernetes bindings (`secret_bindings`). Reading,
writing, and deleting all go through `internal/vault.Service`, the same service layer
the CLI, the web portal, and the REST API all call — there is exactly one code path
that ever seals or opens a secret's payload, in `internal/pqcrypt`.

Nothing here is a new trust boundary: the vault key is derived from the same
`security.master_key` that already protects CA private keys, the LDAP bind password,
and the OIDC client secret (`internal/secret`). Anyone who can decrypt those could
already decrypt secrets; this feature doesn't change goca's blast radius, it extends
what that existing trust boundary protects.

## What "post-quantum" actually buys here

Read this before assuming "post-quantum" means "a stronger cipher." It doesn't —
AES-256-GCM, which goca already used for everything else at rest, **is already
considered post-quantum secure**: Grover's algorithm only halves its effective key
strength, leaving AES-256 at roughly 128-bit security against a quantum adversary.
So "encrypt secrets with a post-quantum algorithm" was, strictly, already true before
this feature existed.

ML-KEM (NIST FIPS 203) is a *key encapsulation mechanism*, not a cipher — it can't
encrypt a secret directly. What it genuinely adds is:

1. **Public-key envelope encryption.** Every secret version gets a random,
   single-use data-encryption key (DEK); the DEK is wrapped to the vault's *public*
   key, not the master key directly. That opens the door to a future write-only role
   — a service that can deposit a secret without being able to decrypt anything back
   out — and means a future vault-key rotation only has to re-wrap DEKs, not
   re-encrypt every payload.
2. **Harvest-now-decrypt-later resistance** for that key-wrapping step specifically —
   the part of the design a quantum adversary could otherwise break retroactively by
   recording ciphertexts today and decrypting them once a sufficiently large quantum
   computer exists. The AEAD payload encryption was never vulnerable to this in the
   first place; the KEM step is what harvest-now-decrypt-later actually targets.
3. **Crypto-agility and a defensible compliance posture** (FIPS 203 / CNSA 2.0), with
   the algorithm recorded in every ciphertext's own header so it can be migrated
   later without a flag day.

The construction is **hybrid X25519 + ML-KEM-768**, not ML-KEM alone — the exact
combination TLS 1.3 negotiates by default as `X25519MLKEM768`. Security holds as long
as *either* primitive holds: a future cryptanalytic break or implementation flaw in
ML-KEM (a comparatively young standard) can't by itself expose the vault, because
X25519 (decades of scrutiny) is independently protecting the same key. Pure ML-KEM
would be a regression against that.

Worth knowing: Go 1.24+'s `crypto/tls` already negotiates `X25519MLKEM768` by default,
so goca's HTTPS listener — and the CSI provider's connection to it — is *already*
PQ-hybrid in transit. This feature is the at-rest half of that same story.

## Quick start

```bash
goca secret create team-a/db/password --label env=prod
goca secret put team-a/db/password 'hunter2'
goca secret get team-a/db/password
# hunter2

goca secret create team-a/web-tls --type certificate --cert 42
goca secret get team-a/web-tls --out-dir ./certs
```

## Secret types

| type | payload | versioned | typical use |
| --- | --- | --- | --- |
| `kv` | an opaque value | yes | passwords, API keys, tokens |
| `file` | a named file | yes | kubeconfigs, credentials JSON, config blobs |
| `certificate` | resolved fresh from a certificate goca issued | no — always current | TLS material for services, mTLS clients |

A `certificate` secret stores nothing of its own beyond a pointer to a certificate
(`cert_id`). Reading it — from the CLI, the web portal, the REST API, or a CSI
Mount — always resolves the certificate's *current* state through `ca.Service`, the
same code path `/certificates/{id}/download/fullchain.pem` uses. Renew or replace the
certificate to rotate the secret; there's no separate "put" for this type.

Materializing a `certificate` secret always produces the same three files:

- `tls.crt` — the full chain (leaf + every issuer up to the root), matching what
  nginx, HAProxy, and Kubernetes `kubernetes.io/tls` Secrets expect to serve directly
- `tls.key` — the decrypted private key
- `ca.crt` — the issuer chain alone (no leaf), for trust bundles

## Versions

A `kv`/`file` secret's history is a strictly append-only list of immutable versions —
`goca secret put` always creates a new one; nothing is ever overwritten. The version
number is reserved and handed to the sealing step inside a single database
transaction, so the number a ciphertext's AAD is bound to can never drift from the
number actually persisted, even racing concurrent writers (see
[Reference](#reference-envelope-format-and-schema) for what AAD binding buys).

`goca secret versions destroy <name> <version>` crypto-shreds one version's
ciphertext in place — the row and its version number stay (so history and audit
trails don't develop gaps), but the content becomes permanently unrecoverable.
Destroying every version leaves the secret with none active; `get` then fails until a
new version is written.

## Managing secrets: CLI, web portal, REST API

### CLI

```bash
goca secret create <name> [--type kv|file|certificate] [--cert <id-or-serial>] \
    [--description ...] [--label k=v] [--rotation-days N]
goca secret put <name> <value>|--file <path>|--stdin [--create]
goca secret get <name> [--version N] [--out <path>] [--out-dir <dir>]  # certificate: --out-dir
goca secret list [--type kv|file|certificate]
goca secret versions <name>
goca secret versions destroy <name> <version>
goca secret rm <name> [--yes]
goca secret bind add <name> --namespace <ns-glob> --service-account <sa-glob> [--expires-in-days N]
goca secret bind list <name>
goca secret bind rm <binding-id>
```

`goca secret put <name> <value> --create` creates the secret (as type `kv`) and
writes its first version in one step, the way `vault kv put` works — useful for
scripting. Every command accepts `--json` for machine-readable output.

### Web portal

Admin-only, at **Secrets** in the navigation bar (`/secrets`). Values are never
rendered into a page — the detail view offers an audited download instead of
inline display, the same pattern certificate private keys already use. See a
secret's page for its version history, metadata, and Kubernetes bindings.

### REST API

Also admin-only, under `/api/v1/secrets*`, addressed by numeric id (consistent with
`/api/v1/cas/{id}` and `/api/v1/certificates/{id}`) rather than by name:

```
GET    /api/v1/secrets                         list (?type=)
POST   /api/v1/secrets                         create
GET    /api/v1/secrets/{id}                    metadata
PATCH  /api/v1/secrets/{id}                     update description/labels/rotation
DELETE /api/v1/secrets/{id}                     delete
POST   /api/v1/secrets/{id}/disable             {"disabled": true|false}
GET    /api/v1/secrets/{id}/materialize         current content, base64, all types
GET    /api/v1/secrets/{id}/versions            list versions
POST   /api/v1/secrets/{id}/versions            write a version ({"value_base64", "content_type"})
GET    /api/v1/secrets/{id}/versions/{version}  read one version, base64
POST   /api/v1/secrets/{id}/versions/{version}/destroy
GET    /api/v1/secrets/{id}/bindings            list bindings
POST   /api/v1/secrets/{id}/bindings            add a binding
DELETE /api/v1/secret-bindings/{id}             revoke a binding
```

Authenticate the same way as every other admin API call — a session cookie (with
its CSRF token) from the portal, or an API token: `Authorization: Bearer goca_...`.

## Kubernetes: mounting secrets with the CSI provider

A separate, lightweight component — `goca run csi-provider` — runs as a DaemonSet
(one pod per node) and speaks the upstream
[Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)'s provider
protocol over a Unix socket. It holds **no database or vault key material of its
own**: every mount request forwards the requesting pod's own bound ServiceAccount
token to the central goca server's `POST /api/v1/vault/fetch`, which is the only
place that authenticates the token, checks it against the secret's bindings, and
decrypts anything.

```
  kubelet ──> secrets-store-csi-driver (DaemonSet, upstream) ──gRPC/UDS──> goca run csi-provider
                                                                                  │ HTTPS + pod's own token
                                                                                  ▼
                                                                    goca server ──> internal/vault
```

**Bindings are the entire authorization decision.** A `SecretProviderClass` can name
any secret it likes; a pod only actually receives it if its own (namespace,
ServiceAccount) — verified server-side from the token, never trusted from anything
the CSI driver or the pod itself claims — matches a binding on that secret. Glob
patterns are supported (`web-*`, `*`), matched with `path.Match` syntax.

**Authentication** works two ways, tried in order:

1. **OIDC/JWKS**, if `csi.issuer_url` is set — verifies tokens locally against the
   cluster's ServiceAccount OIDC issuer's published keys. Works out of the box on
   EKS, GKE, AKS, and any cluster with a public `--service-account-issuer`. No
   per-request round trip to the API server.
2. **TokenReview API**, if `csi.api_server_url` (+ `csi.reviewer_token`) is set —
   asks the cluster's API server directly. This is the path for kind and most
   on-prem clusters, whose default issuer isn't publicly resolvable.

Both can be configured together; the OIDC path is tried first and falls back to
TokenReview whenever it's unreachable. See `CSIConfig` in
`internal/config/config.go` for every field, and
**[k8s-demo/csi/README.md](k8s-demo/csi/README.md)** for the full walkthrough —
installing the upstream driver, the provider DaemonSet, RBAC, example
`SecretProviderClass`es for both a `kv` and a `certificate` secret, and a live
cross-namespace denial + rotation demonstration.

Verified against a real disposable `kind` cluster running the actual upstream
driver: mounted file contents matched for both secret types, a pod running as an
unbound ServiceAccount was denied with the exact "not found or not authorized"
error binding enforcement produces, writing a new version rotated the mounted file
within one `rotationPollInterval` with no pod restart, and the audit log captured
every fetch under the caller's verified Kubernetes identity
(`system:serviceaccount:<namespace>:<name>`).

## Key custody and what compromise means

The vault keypair (hybrid ML-KEM-768 + X25519) is derived deterministically from
`security.master_key`:

```
mlkemSeed  = HKDF-SHA256(masterKey, salt="goca/pq/vault/v1", info="mlkem768-seed", 64)
x25519Seed = HKDF-SHA256(masterKey, salt="goca/pq/vault/v1", info="x25519-priv",   32)
```

This is the same key that already protects every CA private key, the LDAP bind
password, and the OIDC client secret — deliberately, not as an oversight. It means:

- **No new key material to escrow.** The "back up `config.yaml` and the database
  together" story in [SETUP.md](SETUP.md) already covers the secret manager; there
  is nothing additional to protect or lose.
- **Restarts stay unattended.** Nothing needs to be re-entered or unsealed on
  `goca run web` startup — the vault keypair is re-derived from the same config
  every time.
- **The blast radius is exactly what it already was.** Anyone holding
  `config.yaml` (which contains `master_key`) and the database can decrypt every CA
  private key already; they can now also decrypt every secret. This is not a new
  exposure — it's the existing one, extended to cover more data under the same
  lock.

There is currently no separate "unseal" step, no Shamir secret sharing, and no
per-secret access-control beyond the CSI bindings (every admin-authenticated caller
— session or API token — can read every secret; there's no per-secret goca-user
ACL). If your threat model needs those, the custody code sits behind an interface
specifically so a sealed/unseal mode could be added later without a data migration
— but it isn't there today. Treat `config.yaml` and the database backup with the
same care you already apply to your CA's root private key.

## Rotation

**`kv`/`file` secrets**: `goca secret put <name> <new-value>` writes a new version;
the previous one is retained (not overwritten) until explicitly destroyed. A CSI
mount picks up the new version automatically within the driver's
`rotationPollInterval` (2 minutes by default) — no pod restart needed, as long as
the driver was installed with `--set enableSecretRotation=true`.

**`certificate` secrets** rotate by rotating the underlying certificate — renew or
reissue it through the normal CA workflow (`goca cert issue`, the portal, or the
REST API), and every reader of the secret (CLI, web, API, CSI mount) picks up the
new certificate the next time it's read, with no separate action against the secret
itself.

**`rotation_days`** (set at creation or via `goca secret create ... --rotation-days
N` / the metadata edit form) is advisory only: it flags a `kv`/`file` secret
"rotation due" in lists once its current version is older than that many days. It
does not enforce anything or expire the secret — nothing currently automates
rotation itself.

**Vault-key rotation** — re-deriving the vault keypair from a new master key — is
not implemented. Because the design already separates a per-version DEK from the
key that wraps it, this is architecturally possible to add later (re-wrap DEKs
without touching payloads), but doing so today would require decrypting and
re-sealing every version under the new key, since the DEK wrap isn't currently
addressable independently of the sealed payload it's stored alongside (see
[Reference](#reference-envelope-format-and-schema)).

## Threat model and limitations

**In scope / what this defends against:**

- A stolen backup of the database alone, without `config.yaml`'s master key,
  reveals nothing — every payload is AEAD-sealed and every ciphertext is bound via
  AAD to its exact `(secret ID, version)`, so a ciphertext copied to a different row
  or an older/newer version slot fails to decrypt rather than silently succeeding
  with the wrong context.
- A future quantum adversary who recorded today's ciphertexts cannot retroactively
  break the key-wrapping step (harvest-now-decrypt-later resistance), and a break in
  ML-KEM specifically doesn't expose the vault on its own, because X25519 is
  independently protecting the same key (hybrid construction).
- A Kubernetes pod cannot read a secret it isn't explicitly bound to, regardless of
  what any `SecretProviderClass` in its namespace requests — enforced server-side
  from a cryptographically verified ServiceAccount identity, never from anything the
  CSI driver or the requesting pod claims about itself.
- Tampering with a stored ciphertext (bit-flipping, truncation, splicing a stale
  version's payload into a new row) is detected and rejected by the AEAD tag and the
  AAD binding, not silently accepted.

**Explicitly not in scope today** (the schema and interfaces leave room for these;
none are implemented):

- Per-secret access control among goca users — every admin can read every secret.
  The CSI bindings control Kubernetes access only.
- Dynamic/leased secrets with automatic expiry or revocation.
- Transit encryption-as-a-service (using the vault to encrypt/decrypt arbitrary
  application data that isn't itself stored as a goca secret).
- Shamir secret sharing / multi-party unseal.
- Vault-key rotation without a full re-seal of every stored version.
- Rate limiting or anomaly detection on secret reads.

## Troubleshooting

- **`secret "x" is disabled`** — `goca secret bind list`/`get` refuse a disabled
  secret; re-enable it with `goca secret create`'s counterpart, the web portal's
  "Re-enable" button, or `POST .../disable {"disabled": false}`.
- **`not found or not authorized`** (CSI, or the `/api/v1/vault/fetch` endpoint) —
  deliberately identical for "the secret doesn't exist" and "it exists but isn't
  bound to this identity," so the error itself can't be used to enumerate secret
  names. Check `goca secret bind list <name>` for what's actually bound.
- **`k8sauth: OIDC issuer unreachable and no TokenReview fallback is configured`** —
  set at least one of `csi.issuer_url` / `csi.api_server_url` in the server's
  `config.yaml`.
- **A `kv`/`file` secret has "No active version"** — every version was destroyed, or
  none was ever written; `goca secret put` to fix.
- **Version numbers have gaps after concurrent writes** — expected under a race: the
  database's `UNIQUE(secret_id, version)` constraint makes one of two simultaneous
  writers fail cleanly (a "duplicate key" error, safe to retry) rather than either
  silently overwriting the other or persisting a ciphertext whose AAD doesn't match
  its actual stored version.
- CSI-specific issues (driver installation, `CSIDriver` registration, RBAC): see
  [k8s-demo/csi/README.md#troubleshooting](k8s-demo/csi/README.md#troubleshooting).

## Reference: envelope format and schema

Every sealed payload is a single self-describing, versioned, base64 string with a
`pqenc:v1:` prefix (mirroring the `enc:v1:` convention `internal/secret` already
uses for CA keys and config-file secrets):

```
alg(1) ‖ salt(32) ‖ mlkemCiphertext(1088) ‖ ephemeralX25519PublicKey(32) ‖ nonce(12) ‖ wrappedDEK+tag(48) ‖ payloadNonce(12) ‖ payloadCiphertext
```

Two-tier envelope: a random 32-byte data-encryption key (DEK) is generated per
version and used with AES-256-GCM over the actual plaintext; the DEK itself is
wrapped with a key derived from `HKDF-SHA256(mlkemSharedSecret ‖ x25519SharedSecret,
salt, info)`, where the shared secrets come from ML-KEM-768 encapsulation and an
ephemeral X25519 exchange against the vault's public key. This means a 10 MB file
secret pays the ~1.2 KB ML-KEM ciphertext cost once, not per byte.

**AAD binding**: every seal/open call binds the ciphertext to
`goca/secret/v1|<secretID>|<version>`. A ciphertext relocated to a different secret
or version — accidentally or maliciously — fails to decrypt rather than succeeding
with the wrong context.

Data model (`internal/store/store.go`, both the SQLite and PostgreSQL schema
constants):

| table | purpose |
| --- | --- |
| `secrets` | name (unique, path-like), type, labels, `cert_id` for certificate secrets, current version pointer, rotation policy, disabled flag |
| `secret_versions` | immutable: `payload_enc` (the envelope above), `payload_sha256` (doubles as the CSI `object_version`), size, `destroyed` flag, `UNIQUE(secret_id, version)` |
| `secret_bindings` | `k8s_namespace` / `k8s_service_account` (glob patterns), optional expiry |

Kept deliberately separate from `internal/secret` (AES-256-GCM, used for CA private
keys and config-file values) — that package is unchanged by this feature, and
nothing existing was re-encrypted or migrated.
