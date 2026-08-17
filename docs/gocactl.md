# gocactl — the remote client

`gocactl` administers a goca server **over its REST API**. It is the
counterpart to the [`goca`](usage.md) binary:

| | `goca` | `gocactl` |
| --- | --- | --- |
| Runs on | the server host | anywhere |
| Talks to | the database, directly | `https://your-ca/api/v1` |
| Needs | `config.yaml` and the master key | an account, or an API token |
| Can do | everything, including setup | everything your **role** allows |
| Size | ~25 MB | ~7 MB, no database driver linked |

Both binaries ship in the same release archive and the same container image,
and they render output identically — `goca ca list` and `gocactl ca list`
produce byte-for-byte the same table, so runbooks and scripts read the same
either way.

!!! note "Why a second binary"
    `goca` must open the database and decrypt the master key, so administering
    a server used to mean having a shell on it. `gocactl` holds no secrets
    beyond an API token, which is scoped, expiring and revocable — so you can
    hand a colleague day-to-day access without handing them the CA's keys.

## Contents

- [Install](#install)
- [Signing in](#signing-in)
- [Contexts](#contexts)
- [Global flags](#global-flags)
- [Environment variables](#environment-variables)
- [What runs locally](#what-runs-locally)
- [What gocactl cannot do](#what-gocactl-cannot-do)
- [Roles and what they allow](#roles-and-what-they-allow)
- [Command reference](#command-reference)
- [Scripting](#scripting)
- [Differences from goca](#differences-from-goca)

---

## Install

From a release archive — both binaries are inside:

```bash
tar -xzf goca_v1.0.0_linux_amd64.tar.gz && sudo install gocactl /usr/local/bin/
```

From source:

```bash
go install github.com/mevijays/goca/cmd/gocactl@latest
```

Or straight from the container image, with nothing installed at all:

```bash
docker run --rm -it --entrypoint gocactl ghcr.io/mevijays/goca:latest --help
```

## Signing in

```bash
gocactl login --server https://ca.example.com --username alice
```

You are prompted for the password, and the server returns an API token which
is written to `~/.config/gocactl/config.yaml` with mode `0600`. Local accounts
and LDAP accounts both work — `login` uses the same authentication path as the
web portal.

There is **no `--password` flag**, deliberately: it would land in `ps` output
and shell history. For automation, pipe it instead:

```bash
printf '%s' "$CA_PASSWORD" | gocactl login --server https://ca.example.com \
  --username ci-bot --password-stdin --days 30
```

If your server is OIDC-only, there is no password to send — mint a token in
the portal (**Settings → API tokens**) and save it directly:

```bash
gocactl login --server https://ca.example.com --token goca_abc123_...
```

`--days` sets the token's lifetime; the server applies its own maximum
(`security.api_login_token_max_days`, default 90) and its own default
(`security.api_login_token_ttl`, default 30 days). A login token can never be
non-expiring.

`gocactl logout` revokes the token server-side before removing it locally, so
a stolen laptop's token stops working rather than merely disappearing from
that laptop.

Check who the server thinks you are at any time:

```bash
gocactl whoami
```

## Contexts

Like `kubectl`, `gocactl` keeps named contexts so one client can drive several
servers:

```bash
gocactl login --server https://ca-staging.example.com --username alice --context staging
gocactl config get-contexts
gocactl config use-context staging
gocactl --context prod ca list      # one-off, without switching
```

| Command | Does |
| --- | --- |
| `gocactl config get-contexts` | list every context, marking the current one |
| `gocactl config current-context` | print the current context's name |
| `gocactl config use-context <name>` | switch |
| `gocactl config set-context <name> --server … --ca-cert …` | edit or create |
| `gocactl config delete-context <name>` | remove (does **not** revoke the token — use `logout` for that) |
| `gocactl config view` | print the config with token bodies redacted |

The config file is discovered in this order:

1. `--config <path>`
2. `$GOCACTL_CONFIG`
3. `$XDG_CONFIG_HOME/gocactl/config.yaml`
4. `~/.gocactl/config.yaml`, only if it already exists
5. `~/.config/gocactl/config.yaml` — what `login` creates

It is **never** `GOCA_CONFIG` or `~/.goca/config.yaml`: that is the *server's*
config file and it contains `security.master_key`.

## Global flags

| Flag | Meaning |
| --- | --- |
| `--server` | base URL, overriding the context |
| `--token` | API token, overriding the context |
| `--context` | use this context for one command |
| `--config` | path to the gocactl config file |
| `--ca-cert` | trust this CA (PEM) when connecting — for a server using a private certificate |
| `--insecure-skip-verify` | skip TLS verification; prints a warning every time. Lab use only |
| `--json` | emit the server's JSON verbatim |
| `-v, --verbose` | verbose output |

`--ca-cert` is remembered when passed to `login`, so day-to-day commands need
no flags even against a privately-signed server.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `GOCACTL_SERVER` | base URL |
| `GOCACTL_TOKEN` | API token |
| `GOCACTL_CONTEXT` | context to use |
| `GOCACTL_CONFIG` | config file path |
| `GOCACTL_CA_CERT` | CA bundle path |
| `GOCACTL_INSECURE` | `1`/`true` to skip TLS verification |

`GOCACTL_SERVER` + `GOCACTL_TOKEN` are enough on their own — **no config file
is required**, which is what CI jobs and containers want. Prefer the token in
the environment over `--token`, since a flag is visible in `ps`.

## What runs locally

Two commands never contact the server, and that is the point of them:

- **`gocactl csr new`** generates the private key and the CSR on your machine.
  The API's `POST /csr` would generate the key *on the server* and send it
  back over the wire; this does not.
- **`gocactl inspect <file>`** decodes a certificate or CSR locally, so a
  certificate a third party sent you is never uploaded to a server that has no
  reason to see it.

Both work with no server configured at all. The end-to-end test proves it by
running them against a closed port.

```bash
gocactl csr new --common-name app.internal.lan --san app.internal.lan --out ./req
gocactl cert sign --csr ./req/app.internal.lan.csr --days 90 --cert-out app.crt
```

That pair is the recommended flow for anything sensitive: the key is created
where it will be used and only the CSR travels.

## What `gocactl` cannot do

These need the database, the master key or the host itself, and exist only in
`goca`:

| Command | Why |
| --- | --- |
| `goca setup` | creates the config file and the master key |
| `goca run web` / `run csi-provider` | *is* the server |
| `goca install web` / `uninstall web` | writes systemd units on the host |
| `goca ldap test` | reads the server's LDAP configuration |

If a command errors with `not signed in`, run `gocactl login`. If it errors
with `administrator role required`, your account or your token is scoped below
what the command needs — see below.

## Roles and what they allow

Every command is authorised by the **server**, not the client, so `gocactl`
can do exactly what the same account can do in the portal.

Two roles exist. A `user` may issue and manage **their own** certificates and
read the authorities. An `admin` may do everything: manage CAs, users, tokens,
secrets, ACME credentials and the audit log.

An API token carries its own role, and the **effective** role is the lower of
the two. An administrator can therefore mint a deliberately weak token for
automation:

```bash
gocactl token create ci-issuer --role user --days 90
```

That token can issue certificates and nothing else, even though its owner is
an administrator. `gocactl whoami` shows both numbers and says so explicitly
when they differ:

```
  account role:          admin
  effective role:        user
  token:                 ci-issuer (#7)
ℹ this token is scoped below your account role, so admin actions will be refused
```

## Command reference

Every command below behaves exactly as the `goca` equivalent documented in the
[CLI reference](usage.md) — same flags, same output. Only the differences are
noted here.

**Authorities** — `ca list`, `ca show`, `ca create`, `ca export`, `ca default`,
`ca status`, `ca delete`, `ca crl`, `ca pending`, `ca revoke`.
`ca export --with-key` is admin-only; the server refuses the key and the
command exits non-zero.

**Certificates** — `cert issue`, `cert sign`, `cert list`, `cert show`,
`cert export`, `cert renew`, `cert revoke`, `cert hold`, `cert release`,
`cert history`, `cert delete`. A `user` sees and acts on only their own
certificates.

`cert export --p12` sends the bundle password in an `X-Bundle-Password`
header rather than the query string, so it cannot end up in a proxy log.

**Secrets** — `secret list`, `secret create`, `secret get`, `secret put`,
`secret versions`, `secret rm`, `secret bind add|list|rm`. Admin-only.
Sealing and unsealing happen on the server, which holds the master key; the
client only ever sees the plaintext it asked for. See
[Secret Manager](secrets.md).

**Accounts and tokens** — `user list|add|role|passwd|disable|delete` (admin),
`token list|create|revoke`.

**ACME** — `acme status`, `acme eab list|create|disable|delete`,
`acme accounts list|show`. Admin-only. See [ACME](acme-eab.md).

**Audit** — `gocactl audit` reads the audit log (admin-only). This has no
`goca` equivalent; the log was previously visible only in the portal and the
API.

**Local** — `csr new`, `inspect`. See [What runs locally](#what-runs-locally).

**Session** — `login`, `logout`, `whoami`, `config …`, `version`.

## Scripting

`--json` prints the server's response **verbatim**, so what you pipe into `jq`
is exactly what the API returned — no field is dropped by a client-side struct
that has fallen behind:

```bash
gocactl cert list --json | jq -r '.certificates[] | select(.days_left < 30) | .common_name'
```

A CI job needs no config file:

```bash
export GOCACTL_SERVER=https://ca.example.com
export GOCACTL_TOKEN=${{ secrets.GOCA_TOKEN }}
gocactl cert issue --common-name build-$GITHUB_SHA.internal --days 7 --out ./certs
```

Exit status is `0` on success and non-zero on failure, with the *server's*
error message on stderr — `administrator role required`, `you can only access
certificates you requested`, and so on.

## Differences from `goca`

Deliberate, and the complete list:

1. **`csr new` defaults to `rsa-2048`.** `goca` reads the server's configured
   `ca.default_key_type`; `gocactl` generates keys locally and does not ask
   the server for a default it might not be allowed to see. Pass `--key-type`
   to be explicit.
2. **`--actor` does not exist.** The audit log records the authenticated
   account, which is the point of signing in — a remote client does not get to
   name itself.
3. **`gocactl audit` exists and `goca audit` does not.**
4. **Host commands are absent** — see
   [What `gocactl` cannot do](#what-gocactl-cannot-do).

Everything else is intended to be identical, and the test suite enforces it:
one test compares every shared command's flags and their types between the two
binaries, and the end-to-end script diffs their rendered output.
