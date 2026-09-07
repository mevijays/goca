# goca + External Secrets Operator (ESO)

Mounts a goca secret into a real Kubernetes `Secret` object via [ESO's webhook
provider](https://external-secrets.io) — the complement to
[the CSI provider](kubernetes/csi.md), which mounts the same secrets as files
and deliberately never writes them into etcd. Use ESO instead of CSI when an
application genuinely needs a `Secret` object (an env var via
`secretKeyRef`, or another controller that only reads Kubernetes `Secret`s)
and accepts what that costs: the plaintext lands in etcd.

**How it works, in one sentence:** ESO's webhook provider calls
`GET /api/v1/eso/secret` directly — no in-cluster relay, unlike CSI — with a
Kubernetes ServiceAccount bearer token in the `Authorization` header, and
goca verifies that token via TokenReview and checks it against the secret's
bindings, the same authorization model CSI uses.

## The one thing that's different from CSI, and why it matters

CSI's provider forwards the **requesting pod's own token**, freshly minted by
kubelet for that pod, every mount. ESO's webhook provider has no equivalent —
[confirmed against its source](https://github.com/external-secrets/external-secrets/blob/main/providers/v1/webhook/pkg/webhook/models.go):
it authenticates with whatever **static** Kubernetes Secret a `SecretStore`
references, templated into a header. There is no `serviceAccountRef`.

That static credential *can* still be a real ServiceAccount JWT — you put one
in a Secret yourself — so goca's TokenReview verification works unchanged.
But it means the identity goca sees is "this `SecretStore`'s credential", not
"this specific pod". **A `ClusterSecretStore` shares one credential across
the whole cluster**, so every `ExternalSecret` anywhere presents the same
identity to goca — there is no way for goca to tell which namespace actually
asked. For "a team creates `ExternalSecret`s in their own namespace and only
gets their own secrets" to actually be true, **each tenant namespace needs
its own `SecretStore`, its own ServiceAccount, its own token** — this
walkthrough does that.

## Prerequisites

- A goca server with at least one CSI trust domain configured (`gocactl
  csi-auth list`) — see [step 0 of the CSI walkthrough](kubernetes/csi.md#0-enable-csi-on-the-goca-server)
  if you don't have one yet. ESO reuses the exact same trust domains.
- [External Secrets Operator](https://external-secrets.io) installed
  (`helm install external-secrets external-secrets/external-secrets -n
  external-secrets --create-namespace`).
- A secret already in goca, bound the same way you'd bind it for CSI.

## 1. Create the tenant namespace's identity

One ServiceAccount per tenant namespace — this is the whole isolation story,
so don't skip it for a shared one:

```bash
kubectl create namespace team-a
kubectl create serviceaccount eso-reader -n team-a
```

Mint it a token. Like goca's own CSI reviewer token, this is **not
auto-rotated** — pick a duration you're comfortable re-minting before, and
put a reminder somewhere:

```bash
kubectl create token eso-reader -n team-a --duration=8760h > /tmp/token
```

## 2. Bind the secret in goca

Exactly the CSI binding command, with `--auth-method` naming whichever trust
domain this cluster is registered as:

```bash
gocactl secret bind add team-a/db-password \
  --namespace team-a --service-account eso-reader --auth-method my-cluster
```

## 3. The token Secret and the SecretStore

The token from step 1 goes into an ordinary Kubernetes Secret, referenced by
the `SecretStore`:

```bash
kubectl create secret generic goca-eso-token -n team-a --from-file=token=/tmp/token
```

```yaml
# secretstore.yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: goca
  namespace: team-a
spec:
  provider:
    webhook:
      url: "https://goca.example.com/api/v1/eso/secret?key={{ .remoteRef.key }}{{ if .remoteRef.property }}&property={{ .remoteRef.property }}{{ end }}"
      headers:
        Authorization: "Bearer {{ .token.token }}"
        X-Goca-Auth-Method: "my-cluster" # must match --auth-method above
      secrets:
        - name: token
          secretRef:
            name: goca-eso-token
            key: token
      result:
        jsonPath: "$.value"
      # If goca's TLS certificate isn't from a CA this cluster already
      # trusts, add caBundle (base64) or caProvider here - see ESO's docs.
```

```bash
kubectl apply -f secretstore.yaml
```

`{{ .remoteRef.key }}` and `{{ .remoteRef.property }}` are URL-query-escaped
by ESO before this template runs, so a secret name containing `/` (goca names
routinely look like `team-a/db-password`) arrives correctly rather than
turning into an extra path segment — nothing to do on your end for that.

## 4. The ExternalSecret

```yaml
# external-secret.yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: db-password
  namespace: team-a
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: goca
    kind: SecretStore
  target:
    name: db-password        # the Kubernetes Secret this creates
  data:
    - secretKey: password     # the key inside that Secret
      remoteRef:
        key: team-a/db-password
```

```bash
kubectl apply -f external-secret.yaml
kubectl get secret db-password -n team-a -o jsonpath='{.data.password}' | base64 -d
```

A pod consumes it the ordinary way, no goca awareness needed:

```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef: { name: db-password, key: password }
```

## Certificates: `property` selects which file

A `certificate`-type secret has three files (`tls.crt`, `tls.key`, `ca.crt`),
so `/api/v1/eso/secret` refuses to guess — omitting `?property=` on a
multi-file secret is a 400, not an arbitrary pick. Add one `data[]` entry per
file, using `remoteRef.property`:

```yaml
spec:
  target:
    name: web-tls
    template:
      type: kubernetes.io/tls    # so it's a real TLS Secret, not just Opaque
  data:
    - secretKey: tls.crt
      remoteRef: { key: team-a/tls, property: tls.crt }
    - secretKey: tls.key
      remoteRef: { key: team-a/tls, property: tls.key }
    - secretKey: ca.crt
      remoteRef: { key: team-a/tls, property: ca.crt }
```

`property` goes through URL-query-escaping the same as `key`, then a second
`?property=` query parameter on the request.

## What `/api/v1/eso/secret` returns

```json
{
  "name": "team-a/db-password",
  "property": "text/plain",
  "version": "2d711642...",
  "value": "hunter2",
  "value_base64": "aHVudGVyMg=="
}
```

`value` is present only when the content is valid UTF-8 (every goca secret
type is, in practice — PEM certificates/keys and kv/file text). `value_base64`
is always present. Point `result.jsonPath` at `$.value` for the ordinary
case; use `$.value_base64` with ESO's `decodingStrategy: Base64` on the
`data[]` entry for anything binary.

A secret that doesn't exist and one that exists but isn't bound to this
identity return the identical 404 — the same non-enumerability property
`/api/v1/vault/fetch` (the CSI path) already has.

## Troubleshooting

- **`ExternalSecret` status shows a fetch error** —
  `kubectl describe externalsecret <name> -n <namespace>` surfaces the
  error text from goca verbatim. `not found or not authorized` means the
  binding is missing or scoped to the wrong namespace/ServiceAccount/trust
  domain — check `gocactl secret bind list <name>`.
- **`secret ... has N parts; add ?property=`** — a certificate secret fetched
  with no `property`. Add the three `data[]` entries from the certificates
  section above.
- **`token rejected`** — the token in the `goca-eso-token` Secret expired.
  Re-mint it (step 1) and `kubectl create secret generic ... --from-file`
  again (or `kubectl create secret ... -o yaml --dry-run=client | kubectl
  apply -f -` to update in place).
- **It worked once, then stopped** — same as above; ServiceAccount tokens
  from `kubectl create token` are not renewed automatically. Put the
  `--duration` reminder in your team's runbook, or automate re-minting with a
  CronJob if this is more than a one-off.
- **A different namespace can read this secret** — you're on a shared
  `ClusterSecretStore` or a shared token. See "The one thing that's
  different from CSI" above; give the namespace its own `SecretStore` and its
  own ServiceAccount.
