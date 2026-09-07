# Observability and eventing

goca exposes three ways to watch what it does: Prometheus metrics, signed
webhook events, and a paginated audit log you can export. All three are
additive — nothing changes about how you issue certificates or manage secrets.

## Metrics

`GET /metrics` serves Prometheus text format, admin-gated like every other
`/api/v1` route (it is not itself under `/api/v1`, but goes through the same
auth). It is **not** left unauthenticated the way a typical Prometheus
endpoint is — `goca_auth_login_total{result}` below is a live counter of
login outcomes, which is a real side channel if anyone on the network can
poll it (watching whether their own credential-stuffing attempts are
landing, independent of whatever the login rate limiter itself lets them
observe), on top of per-CA issuance and secret counts. Point your scrape
config at it with an admin-role API token:

```bash
goca token create prometheus --role admin --days 3650
```

```
goca_ca_cert_issued_total{ca="prod",profile="server"} 42
goca_ca_cert_revoked_total{reason="superseded"} 3
goca_vault_secret_read_total{type="kv",result="success"} 128
goca_auth_login_total{result="failure"} 7
```

Every metric is in the `goca_` namespace and uses low-cardinality labels only
(a CA name, a profile, a status) so the series count stays flat as traffic
grows. The full list:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `goca_ca_cert_issued_total` | `ca`, `profile` | certificates issued |
| `goca_ca_cert_revoked_total` | `reason` | certificates revoked |
| `goca_ca_cert_search_total` | `status` | certificate searches |
| `goca_vault_secret_created_total` | `type` | secrets created |
| `goca_vault_secret_read_total` | `type`, `result` | secret reads (success/denied) |
| `goca_vault_secret_put_total` | `type` | secret values written |
| `goca_vault_secret_deleted_total` | — | secrets deleted |
| `goca_acme_order_total` | `status` | ACME orders |
| `goca_acme_account_total` | `status` | ACME accounts |
| `goca_acme_challenge_total` | `status` | ACME challenges |
| `goca_auth_login_total` | `result` | logins (success/failure) |
| `goca_auth_token_total` | `action` | API tokens issued/revoked |

A minimal Prometheus scrape config, with the admin token from above in a file
Prometheus reads (`credentials_file`, not `credentials`, so the token itself
never has to sit in `prometheus.yml`):

```yaml
scrape_configs:
  - job_name: goca
    static_configs:
      - targets: ["ca.example.com:8443"]
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/goca-ca.crt
    authorization:
      credentials_file: /etc/prometheus/goca-metrics-token
```

## Webhooks

A webhook is a named HTTP endpoint that receives a signed JSON event whenever
goca records an audit action matching its filter. This is how you fan goca
activity out to Slack, PagerDuty, an SIEM, or a custom integration.

### Creating one

```
gocactl webhook create ops \
  --url https://hooks.example.com/goca \
  --events '*' \
  --secret s3cr3t
```

- `--url` must be `http://` or `https://` and cannot point at loopback or a
  link-local address (which is where every major cloud provider serves
  instance-metadata credentials) — both at creation time and, so a redirect
  or a hostname that resolves differently later can't be used to route
  around that, at the moment goca actually connects to deliver an event. An
  ordinary receiver elsewhere on your network (including a private,
  non-public address) is fine.
- `--events` is a comma-separated list of **action prefixes**. `cert` matches
  `cert.issue` and `cert.revoke`; `cert.issue,secret.put` matches exactly those
  two; `*` matches everything.
- `--secret` is the HMAC-SHA256 signing key. It is encrypted at rest with the
  master key and is never returned by any endpoint. Omit it for unsigned
  deliveries (not recommended).

The same operations exist in the web portal and the REST API
(`POST /api/v1/webhooks`, admin-only).

### The event

Each delivery is a `POST` with `Content-Type: application/json`:

```json
{
  "id": "evt-1712345678901234567",
  "ts": "2026-04-06T12:00:00Z",
  "actor": "admin",
  "action": "cert.issue",
  "target": "prod",
  "detail": "cn=app.internal.lan",
  "ip": "10.0.0.1"
}
```

Headers:

| Header | Value |
| --- | --- |
| `X-Goca-Event` | the audit action (e.g. `cert.issue`) |
| `X-Goca-Delivery` | the delivery id (stable, for de-duplication) |
| `X-Goca-Signature` | `sha256=<hex>` — HMAC-SHA256 of the raw body under the secret |

Verify the signature before trusting the body:

```python
import hmac, hashlib
def verify(body: bytes, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

### Delivery, retry, and dead-letter

Delivery is **durable**, not fire-and-forget. When an action is recorded, goca
writes a row to `webhook_deliveries` and a background worker performs the HTTP
call. A 2xx response marks the delivery `delivered`. Anything else is retried
with exponential backoff (30s, 60s, 120s, … capped at 15 minutes) and, after
five attempts, is marked `dead` so it stops consuming retries but stays on
record.

```
gocactl webhook deliveries 1
id  event        status     attempts  last status  last error
7   cert.issue   delivered  1         200
6   secret.put   failed     3         502          unexpected status 502
5   cert.issue   dead       5         503          unexpected status 503
```

`gocactl webhook disable 1` (or `--enable`) pauses a webhook without deleting
it; queued deliveries for a disabled webhook are simply skipped.

## Audit log export

The audit log records every state-changing action (who, what, when, from
where). It is paginated by cursor so large logs can be walked without loading
them all at once, and `gocactl audit export` walks the whole log for you:

```
gocactl audit export --format csv -o audit-2026-04.csv
gocactl audit export --format json --page-size 1000
```

The CSV columns are `id,ts,actor,action,target,detail,ip` with RFC 3339 UTC
timestamps. The REST endpoint behind it is `GET /api/v1/audit?limit=N&cursor=C`,
which returns `{"entries": [...], "next_cursor": "..."}` — pass `next_cursor`
back as `cursor` to fetch the next page; an empty `next_cursor` means you have
reached the beginning.

## How it fits together

```
  action (cert.issue, secret.put, ...)
        │
        ▼
  ca.Service.recordAudit ──► audit_log table ──► /api/v1/audit, gocactl audit export
        │
        └──► event sink ──► webhook_deliveries ──► dispatcher worker
                                                          │
                                                          ▼
                                              signed POST to each matching webhook
```

The single funnel is `ca.Service.recordAudit`: every service (CA, vault, ACME)
records its actions through it, so a webhook sees the complete picture without
each service knowing webhooks exist.