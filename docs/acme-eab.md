# ACME for private domains (External Account Binding only)

goca can act as an [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) ACME
server, which lets [cert-manager](https://cert-manager.io) — and any other
ACME client, `certbot`, `acme.sh`, `lego`, Traefik, Caddy — request and renew
certificates from it automatically.

It implements **External Account Binding (EAB) only**. There is no HTTP-01 or
DNS-01 challenge validation. This is deliberate: those challenge types exist
to prove domain ownership to a CA that has no other reason to trust you —
that's the right model for a public CA issuing for the open internet, and the
wrong one for a private CA issuing for `*.svc.cluster-a.internal`, a zone the
public internet can't even resolve. For goca, the trust decision is made once,
by an operator, when they hand a cluster a pre-shared secret. Nothing about
domain reachability enters into it.

If you need real challenge-based validation (a public-facing CA, or you want
per-order proof of control regardless of the pre-shared secret), goca isn't
the tool for that — see [README.md](index.md) for what it's built for
instead. For everything internal, EAB-only is simpler to operate and exactly
matches how you already trust the cluster: it's on your network, and it holds
a secret you gave it.

Setup and CLI basics live in [SETUP.md](setup.md) and [USAGE.md](usage.md).
This document is the complete story for the ACME side. Want a runnable
copy-paste version instead of reading first? See
**[kubernetes/cert-manager.md](kubernetes/cert-manager.md)** — cert-manager install, the exact
`ClusterIssuer`/`Certificate` YAML, applied in order.

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Creating an EAB credential](#creating-an-eab-credential)
  - [CLI](#cli)
  - [Web portal](#web-portal)
  - [REST API](#rest-api)
- [Wiring up cert-manager](#wiring-up-cert-manager)
  - [The Secret and ClusterIssuer](#the-secret-and-clusterissuer)
  - [Requesting a certificate](#requesting-a-certificate)
  - [Namespaced Issuer instead of ClusterIssuer](#namespaced-issuer-instead-of-clusterissuer)
  - [Multiple clusters, multiple credentials](#multiple-clusters-multiple-credentials)
- [Scoping: which CA, which domains, how many accounts](#scoping-which-ca-which-domains-how-many-accounts)
- [What an ACME-issued certificate looks like inside goca](#what-an-acme-issued-certificate-looks-like-inside-goca)
- [Revoking, holding and rotating](#revoking-holding-and-rotating)
- [Managing credentials day to day](#managing-credentials-day-to-day)
- [Verifying without cert-manager](#verifying-without-cert-manager)
- [Troubleshooting](#troubleshooting)
- [Security model and limitations](#security-model-and-limitations)
- [Protocol reference](#protocol-reference)

---

## How it works

1. You create an **EAB credential** in goca: a public `keyID` and a secret
   HMAC key, bound to one issuing authority, one certificate profile, and
   optionally a list of domains it may request and a cap on how many ACME
   accounts may ever be bootstrapped with it.
2. You put that `keyID` and key into a Kubernetes `Secret` and reference it
   from a cert-manager `ClusterIssuer`.
3. cert-manager registers an ACME account with goca, proving it holds the
   secret. From that point on it signs every further request with its own
   key — the shared secret is used exactly once, at registration.
4. When cert-manager requests a certificate, goca checks the requested names
   against the credential's allowed domains (if any), signs it immediately —
   **no challenge is ever presented or checked** — and returns it.
5. The certificate that comes back is an entirely ordinary goca certificate:
   searchable, renewable, revocable, exportable, from the CLI, the API or the
   portal, exactly like one issued any other way.

## Quick start

```bash
# 1. Create a credential scoped to one cluster's zone.
goca acme eab create cluster-a \
    --ca acme-issuing-ca \
    --allowed-domain '*.svc.cluster-a.internal' \
    --max-accounts 1
```

This prints a `keyID` and an HMAC key once. Put them in a Secret:

```bash
kubectl create secret generic goca-eab \
    --namespace cert-manager \
    --from-literal=hmac-key='<the HMAC key from above>'
```

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: goca
spec:
  acme:
    server: https://ca.example.com/acme/directory
    privateKeySecretRef:
      name: goca-acme-account-key
    externalAccountBinding:
      keyID: <the keyID from above>
      keySecretRef:
        name: goca-eab
        key: hmac-key
    solvers: []
```

That's the whole configuration. `solvers: []` is correct and stays empty —
see [why below](#wiring-up-cert-manager). Request a certificate the normal
cert-manager way and it's issued immediately, no challenge round trip:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app-tls
  namespace: default
spec:
  secretName: app-tls
  issuerRef:
    name: goca
    kind: ClusterIssuer
  dnsNames:
    - app.svc.cluster-a.internal
```

## Creating an EAB credential

Every field is available from all three interfaces, because they all call the
same `internal/acme` service. Fields:

| Field | Meaning | Default |
| --- | --- | --- |
| name | Label for lists, audit entries and the portal | *(required)* |
| CA | Which authority signs certificates from accounts using this credential | the default issuing CA, resolved fresh per order |
| profile | Certificate profile (`server`, `client`, `server-client`, `code-signing`, `email`) | `server` |
| days | Certificate validity | the CA's/global default |
| allowed domains | Glob patterns an order's identifiers must match | unrestricted |
| max accounts | Cap on ACME accounts bootstrapped with this credential | unlimited |
| expires in days | Auto-disable the credential itself after N days | never |

### CLI

```bash
goca acme eab create cluster-a \
    --ca acme-issuing-ca \
    --profile server \
    --days 90 \
    --allowed-domain '*.svc.cluster-a.internal' \
    --allowed-domain '*.internal.lab' \
    --max-accounts 1 \
    --expires-in-days 0
```

The HMAC key is printed once — copy it before it's out of your terminal. If
you lose it, delete the credential and create a new one; there is no way to
retrieve it again (it's stored encrypted with the master key, the same as
every other secret goca holds, and never decrypted for display).

```bash
goca acme eab list                    # table of every credential
goca acme eab show cluster-a          # by name (if unambiguous), id, or key id
goca acme eab disable cluster-a       # stop new accounts; existing ones keep renewing
goca acme eab delete cluster-a --yes  # only works once no accounts reference it
goca acme accounts list               # every account any credential has bootstrapped
goca acme accounts show 1             # one account's orders
goca acme status                      # directory URL + a quick summary
```

Full flag reference: [USAGE.md](usage.md) covers every other command; the
`acme` subtree isn't duplicated there in as much depth as here since this file
is the canonical reference for it.

### Web portal

Sign in as an admin and open **ACME** in the top navigation
(`/settings/acme`). The page shows:

- the directory URL, ready to paste into a `ClusterIssuer`
- a form to create a new credential (the same fields as the CLI)
- the HMAC key, shown once, immediately after creation
- every credential, with its scope, account count and state, and
  disable/delete actions
- every account that has registered, which credential bootstrapped it, its
  contact address and when it was last used

### REST API

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"cluster-a","ca":"acme-issuing-ca",
       "allowed_domains":["*.svc.cluster-a.internal"],"max_accounts":1}' \
  https://ca.example.com/api/v1/acme/eab
```

```json
{
  "credential": { "id": 1, "key_id": "6z9kx5d8vdnvqjeermc7", "name": "cluster-a", "...": "..." },
  "hmac_key": "3tVcO2s_4dn2hUdjuzCk0axZVSXMjDaL9DTuyzG3K4o"
}
```

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/acme/eab` | list credentials |
| `POST` | `/api/v1/acme/eab` | create; response includes the HMAC key once |
| `GET` | `/api/v1/acme/eab/{id}` | one credential |
| `POST` | `/api/v1/acme/eab/{id}/disable` | `{"disabled":true\|false}` |
| `DELETE` | `/api/v1/acme/eab/{id}` | refused while any account references it |
| `GET` | `/api/v1/acme/accounts` | every registered account |
| `GET` | `/api/v1/acme/accounts/{id}` | one account |
| `GET` | `/api/v1/acme/accounts/{id}/orders` | its orders |

All admin-only, authenticated the normal goca way (session cookie or bearer
token) — this is management of the ACME *feature*, not the ACME protocol
itself, which is unauthenticated at this layer and instead authenticates
every request through its own JWS/EAB mechanism at `/acme/*`.

---

## Wiring up cert-manager

### The Secret and ClusterIssuer

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: goca-eab
  namespace: cert-manager
type: Opaque
stringData:
  hmac-key: 3tVcO2s_4dn2hUdjuzCk0axZVSXMjDaL9DTuyzG3K4o
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: goca
spec:
  acme:
    server: https://ca.example.com/acme/directory
    # cert-manager creates its own account key and stores it here on first
    # use - this is not the EAB secret, and you don't need to create it.
    privateKeySecretRef:
      name: goca-acme-account-key
    externalAccountBinding:
      keyID: 6z9kx5d8vdnvqjeermc7
      keySecretRef:
        name: goca-eab
        key: hmac-key
      # keyAlgorithm is deprecated in cert-manager >= 1.3 (cert-manager's
      # ACME client hardcodes HS256, which is what goca signs with) - omit it.
    solvers: []
```

**Why `solvers: []` and not an HTTP-01/DNS-01 entry:** cert-manager's order
controller checks each authorization's status before deciding whether it
needs a solver at all. When an authorization already arrives `"valid"` — which
every one of goca's does, since EAB was the whole trust decision — cert-manager
logs `"Authorization already valid, not creating Challenge resource"` and
moves straight to finalizing. No HTTP endpoint, no DNS record, no solver is
ever invoked. An empty `solvers` list is correct, not a placeholder for
something you still need to configure.

`email` is optional and unused by goca; omit it or set anything you like —
it's stored in the account's `contact` field for your own records.

### Requesting a certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app-tls
  namespace: default
spec:
  secretName: app-tls
  duration: 2160h    # 90 days - cert-manager renews automatically before this
  issuerRef:
    name: goca
    kind: ClusterIssuer
  dnsNames:
    - app.svc.cluster-a.internal
    - app.internal.lab
```

Or via an Ingress annotation:

```yaml
metadata:
  annotations:
    cert-manager.io/cluster-issuer: goca
```

cert-manager creates the `Order`, goca signs it on the spot, and the
certificate lands in the `app-tls` Secret within a few seconds — there's no
challenge propagation delay to wait out.

### Namespaced Issuer instead of ClusterIssuer

Identical shape, `kind: Issuer`, scoped to one namespace:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: goca
  namespace: team-a
spec:
  acme:
    server: https://ca.example.com/acme/directory
    privateKeySecretRef:
      name: goca-acme-account-key
    externalAccountBinding:
      keyID: 6z9kx5d8vdnvqjeermc7
      keySecretRef:
        name: goca-eab
        key: hmac-key
    solvers: []
```

The `Secret` referenced by `keySecretRef` must live in the same namespace as
the `Issuer`.

### Multiple clusters, multiple credentials

The common pattern: one EAB credential per cluster (or per environment),
scoped to that cluster's own zone, with `--max-accounts 1` so a leaked keyID
can't silently be used to bootstrap a second account:

```bash
goca acme eab create cluster-a --allowed-domain '*.svc.cluster-a.internal' --max-accounts 1
goca acme eab create cluster-b --allowed-domain '*.svc.cluster-b.internal' --max-accounts 1
goca acme eab create staging   --allowed-domain '*.staging.internal.lab'   --ca staging-issuing-ca
```

Each becomes its own `ClusterIssuer` in its own cluster, pointed at the same
goca server. Revoking one cluster's access is `goca acme eab disable
cluster-a` — it stops new registrations immediately; that cluster's existing
account (if compromised, you'd also want to revoke the certificates it
holds — see [below](#revoking-holding-and-rotating)) can no longer be
recreated if it's ever lost, but a live one you must handle explicitly since
it authenticates with its own key from then on, not the disabled secret.

---

## Scoping: which CA, which domains, how many accounts

**CA**: `--ca` binds a credential to one specific authority. Leave it unset
and each order resolves the *default* issuing authority at request time —
useful if you rotate which CA is "current" and want every EAB-bootstrapped
client to follow automatically. Set it explicitly when a credential must
always issue from one particular authority regardless of what's default.

**Profile**: sets key usage / extended key usage on every certificate the
credential's accounts request. `server` (default) is right for the
overwhelming majority of cert-manager use — TLS server certificates for
ingress, services, mTLS-terminating sidecars. Use `client` or
`server-client` for mutual-TLS setups where the certificate also needs to
authenticate outbound.

**Allowed domains**: shell-glob patterns, matched case-insensitively.
`*` matches across dot boundaries — `*.svc.cluster-a.internal` permits
`app.svc.cluster-a.internal` **and** `a.b.svc.cluster-a.internal`, since this
is an access-control boundary ("what zone can this credential touch"), not
TLS wildcard-certificate semantics. A bare zone like `*.svc.cluster-a.internal`
does *not* itself match `svc.cluster-a.internal` — there must be at least one
label before the pattern's fixed suffix. An order requesting a name outside
every pattern is rejected with `rejectedIdentifier` before anything is signed.
Leave it empty for no restriction beyond whatever the CA itself constrains
(via its own `--permitted-dns`, if you set one when creating the authority).

Wildcard *certificate* requests work normally — order the identifier
`*.svc.cluster-a.internal` itself, and it's checked against your allowed-domain
patterns the same way a concrete name is.

**Max accounts**: caps how many times `new-account` can successfully register
a *new* key against this credential. `1` is the right choice for the normal
one-issuer-per-cluster pattern, since it means the credential can bootstrap
exactly the one cert-manager instance you intend and nothing else, even if the
`keyID`/HMAC key pair leaks afterward. Re-registering with the *same* account
key is always idempotent regardless of this limit — it just returns the
existing account (RFC 8555 requires this) — so cert-manager restarting or
re-applying its `ClusterIssuer` never trips the cap.

**Credential expiry**: `--expires-in-days` stops the credential bootstrapping
further accounts after that many days, without touching anything it already
created. Use it for a short-lived onboarding window; leave it at the default
(never) for a credential you intend to be permanent infrastructure.

---

## What an ACME-issued certificate looks like inside goca

Nothing special. `Finalize` calls the exact same `Issue()` the CLI's
`goca cert issue`, the portal's request form and `POST /api/v1/certificates`
all call, so from the moment it's signed it's an ordinary row in the same
table. The one marker is its `requested_by` field, which is set to
`acme:<credential name>` instead of a username:

```bash
goca cert list --query 'acme:cluster-a'
```

```
ID  COMMON NAME                 AUTHORITY        PROFILE  STATUS  EXPIRES     REQUESTED BY
1   app.svc.cluster-a.internal  ACME Issuing CA  server   active  2027-09-16  acme:cluster-a
```

Everything else works exactly as documented in [USAGE.md](usage.md#goca-cert):
`goca cert show`, `export`, `renew`, `revoke`, `hold`. The private key is
**never** stored — cert-manager (like any well-behaved ACME client) generates
its own key and only ever sends goca a CSR, so there is nothing for goca to
retain even if you wanted it to.

## Revoking, holding and rotating

**Routine renewal** is entirely cert-manager's job: it re-runs the ACME flow
before the certificate expires, using its already-registered account, and
goca issues a fresh one the same way. You don't need to do anything.

**Revoking a certificate cert-manager doesn't know is compromised** — do it in
goca directly, the same as any other certificate:

```bash
goca cert revoke 1 --reason keyCompromise --crl
```

cert-manager finds out the normal way (the certificate no longer verifies /
its CRL entry appears) and re-issues on its own next reconcile, or force it:

```bash
kubectl delete secret app-tls -n default   # cert-manager notices and re-requests
```

**Revoking through ACME itself** also works — cert-manager's `RevokeCert` call
is honored, authenticated either by the account that requested the
certificate or by the certificate's own private key, per RFC 8555 §7.6.

**A whole credential going bad** (leaked keyID/HMAC pair, decommissioned
cluster): `goca acme eab disable <name>` stops it bootstrapping anything new.
If the account it already created might be compromised too, revoke that
account's certificates directly:

```bash
goca cert revoke-many --query 'acme:cluster-a' --reason keyCompromise --yes --crl
```

## Managing credentials day to day

```bash
goca acme eab list                     # everything at a glance: scope, accounts, state
goca acme accounts list                # who has actually registered
goca acme accounts show <id>           # one account's order history
goca token create ...                  # unrelated: that's a goca API token, not an EAB credential
```

The portal's **ACME** page (admin-only) mirrors all of this with the same
reveal-once-key UX as API tokens.

## Verifying without cert-manager

Any RFC 8555 client works. A minimal Go example using the same client library
this feature's own tests are verified against
(`golang.org/x/crypto/acme`), useful for a quick sanity check before wiring up
a real cluster:

```go
client := &acme.Client{
    Key:          accountKey, // any crypto.Signer, e.g. an ECDSA P-256 key
    DirectoryURL: "https://ca.example.com/acme/directory",
}
_, _ = client.Discover(ctx)
_, err := client.Register(ctx, &acme.Account{
    ExternalAccountBinding: &acme.ExternalAccountBinding{
        KID: "6z9kx5d8vdnvqjeermc7",
        Key: hmacKeyBytes, // base64url-decoded
    },
}, acme.AcceptTOS)
order, _ := client.AuthorizeOrder(ctx, acme.DomainIDs("app.svc.cluster-a.internal"))
ready, _ := client.WaitOrder(ctx, order.URI)     // returns immediately: already "ready"
der, _, _ := client.CreateOrderCert(ctx, ready.FinalizeURL, csrDER, true)
```

`certbot` also speaks RFC 8555 with EAB (`--eab-kid` / `--eab-hmac-key`) if you
want to test from the command line without writing any code:

```bash
certbot certonly --standalone --non-interactive \
  --server https://ca.example.com/acme/directory \
  --eab-kid 6z9kx5d8vdnvqjeermc7 --eab-hmac-key 3tVcO2s_4dn2hUdjuzCk0axZVSXMjDaL9DTuyzG3K4o \
  -d app.svc.cluster-a.internal
```

(`--standalone` is only there to satisfy certbot's requirement that some
plugin be selected; since every authorization already comes back valid, no
client, cert-manager included, should need to actually engage it — but
certbot's own logging around plugin selection isn't something this project
controls, so don't be surprised if it mentions HTTP-01 in passing.)

## Troubleshooting

**`externalAccountRequired` errors, or registration fails outright** — check
`goca acme eab list`: is the credential disabled, expired, or already at its
`max_accounts` limit? `goca acme eab show <name>` gives the exact state.

**`rejectedIdentifier`** — the requested name doesn't match any of the
credential's `--allowed-domain` patterns. `goca acme eab show <name>` prints
them; remember `*` matches across dot boundaries but a pattern like
`*.internal.lab` never matches the bare `internal.lab` itself.

**`badCSR`** — the CSR's DNS names don't exactly match the order's
identifiers. This usually means the ACME client and the `Certificate`
resource's `dnsNames` disagree, or a client is asking for more names than the
order it created covers; it is not something goca-side configuration affects.

**cert-manager's `Order` sits at `pending`, never reaches `ready`** — this
would mean an authorization did *not* come back `"valid"`, which shouldn't
happen in normal operation. Check `goca acme accounts show <id>` for the
order in question, and check the audit log (`goca` writes an audit entry for
every account rejection and issuance) for what happened.

**`orderNotReady`** on finalize — the client tried to finalize before the
order reached `ready`; a spec-compliant client shouldn't do this, since goca's
orders are `ready` from the moment they're created.

**A `ClusterIssuer` reports `Ready: False`, no clear error** — check
`kubectl describe clusterissuer goca`; cert-manager surfaces the ACME
directory-fetch or registration error there directly. Confirm the `server`
URL resolves and returns JSON at `/acme/directory` from inside the cluster
(`kubectl run -it --rm debug --image=curlimages/curl -- curl -s
https://ca.example.com/acme/directory`).

**Testing goca itself** — `goca acme status` shows the directory URL and a
credential/account summary without touching Kubernetes at all.

## Security model and limitations

- **EAB is the entire trust decision.** There is no HTTP-01, DNS-01, or
  TLS-ALPN-01 challenge implementation. Anyone who can present a valid,
  usable EAB `keyID` + HMAC key can bootstrap an account and — subject to
  that credential's domain scope — request certificates. Protect the HMAC key
  exactly as you would a private key: it's a Kubernetes `Secret`, transmitted
  once, and never needs to leave the cluster it was created for.
- **No key rollover (RFC 8555 §7.3.5).** An account's key is fixed at
  registration. If a cluster's account key is compromised, disable its EAB
  credential (which only stops *new* registrations) and revoke the
  certificates that account holds; cert-manager will re-register a fresh
  account against a newly created credential.
- **No pre-authorization (`newAuthz`).** Every authorization is created as
  part of an order; there's no way to authorize a name ahead of requesting a
  certificate for it. cert-manager doesn't use this endpoint, so it doesn't
  matter for the target use case.
- **Identifiers are DNS names only.** IP-address identifiers
  ([RFC 8738](https://www.rfc-editor.org/rfc/rfc8738)) are rejected with
  `unsupportedIdentifier`. Request certificates for IPs the normal way
  instead (`goca cert issue --san 10.0.0.5`).
- **`notBefore`/`notAfter` in an order are accepted and ignored.** Validity is
  controlled entirely by the EAB credential's `--days` (or the CA/global
  default) — there's no per-order pinned window.
- **Nonces are in-memory**, not persisted to the database. A goca restart
  mid-flow invalidates outstanding nonces; every compliant ACME client
  (including cert-manager's) already retries transparently on `badNonce`, so
  this is not user-visible in practice.

## Protocol reference

Directory: `GET /acme/directory` (no auth). Everything else is signed JWS,
authenticated per RFC 8555 §6 — `jwk` for `new-account`, `kid` (the account
URL) for everything else, except `revoke-cert` which accepts either.

| Method | Path | RFC 8555 § |
| --- | --- | --- |
| `GET`/`HEAD` | `/acme/new-nonce` | 7.2 |
| `POST` | `/acme/new-account` | 7.3 |
| `POST` | `/acme/account/{id}` | 7.3.2, 7.3.6 (fetch / update contact / deactivate) |
| `POST` | `/acme/new-order` | 7.4 |
| `POST` | `/acme/order/{id}` | 7.1.3 (POST-as-GET) |
| `POST` | `/acme/order/{id}/finalize` | 7.4 |
| `POST` | `/acme/authz/{id}` | 7.5 |
| `POST` | `/acme/challenge/{id}` | 7.5.1 — always already `"valid"` |
| `GET`/`POST` | `/acme/cert/{id}` | 7.4.2 |
| `POST` | `/acme/revoke-cert` | 7.6 |

Not implemented, and not advertised in the directory (both are optional per
the spec): `newAuthz` (pre-authorization) and `keyChange` (account key
rollover).
