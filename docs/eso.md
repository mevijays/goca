# goca + External Secrets Operator (ESO)

Mounts a goca secret into a real Kubernetes `Secret` object — the complement
to [the CSI provider](kubernetes/csi.md), which mounts the same secrets as
files and deliberately never writes them into etcd. Use ESO instead of CSI
when an application genuinely needs a `Secret` object (an env var via
`secretKeyRef`, or another controller that only reads Kubernetes `Secret`s)
and accepts what that costs: the plaintext lands in etcd.

Both authenticate against goca's `GET /api/v1/eso/secret` the same way CSI
does — a Kubernetes ServiceAccount bearer token, verified by goca via
TokenReview and checked against the secret's bindings — but they get that
token to goca differently:

| | Native provider | Generic webhook provider |
| --- | --- | --- |
| Token | Live, minted fresh per fetch via the Kubernetes TokenRequest API — nothing to provision or rotate | Static: a Secret you create and re-mint by hand before it expires |
| Namespace isolation | Kubernetes RBAC on the ESO controller's own ServiceAccount | One `SecretStore` + one dedicated ServiceAccount per tenant namespace |
| Runs on | A custom-built ESO controller image (this provider isn't in an official release yet) | Any official ESO install, unmodified |
| Setup | RBAC once; a `SecretStore` per tenant namespace, no token to manage | A token to mint and a Secret to create, per tenant namespace |

If you can run a custom ESO image, the native provider is the better
default — no manual rotation, and isolation comes from Kubernetes' own RBAC
rather than a Secret you have to keep fresh. The generic webhook provider is
what to reach for against an official, unmodified ESO install.

## Native provider

The provider lives at `providers/v1/goca` in
[a fork of external-secrets/external-secrets](https://github.com/external-secrets/external-secrets)
(not yet upstreamed — see "Getting the image" below). It authenticates by
asking the Kubernetes API directly for a fresh token for a *named*
ServiceAccount — the same `TokenRequest` mechanism kubelet uses internally
for CSI, just invoked on demand instead of mounted. No static Secret is ever
created.

### 1. RBAC: let the ESO controller mint tokens for your tenant's ServiceAccount

```bash
kubectl create namespace team-a
kubectl create serviceaccount eso-reader -n team-a
```

```yaml
# rbac.yaml - grants ESO's controller permission to mint tokens for
# team-a/eso-reader specifically, not any ServiceAccount cluster-wide.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mint-eso-reader-token
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    resourceNames: ["eso-reader"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: eso-controller-mint-eso-reader-token
  namespace: team-a
subjects:
  - kind: ServiceAccount
    name: external-secrets    # the ESO controller's own ServiceAccount
    namespace: external-secrets   # check yours: some installs use external-secrets-system
roleRef:
  kind: Role
  name: mint-eso-reader-token
  apiGroup: rbac.authorization.k8s.io
```

```bash
kubectl apply -f rbac.yaml
```

Find the controller's actual namespace and ServiceAccount name for your
install rather than assuming — it varies by how ESO was deployed:

```bash
kubectl get deploy -A -o jsonpath='{range .items[?(@.metadata.name=="external-secrets")]}{.metadata.namespace}{"\t"}{.spec.template.spec.serviceAccountName}{"\n"}{end}'
```

This `Role`/`RoleBinding` pair *is* the isolation boundary: repeat it per
tenant namespace, each scoped to that namespace's own ServiceAccount, and the
ESO controller can only ever mint tokens for the ones you've explicitly
granted — Kubernetes enforces it, not goca.

### 2. Bind the secret in goca

Same as always:

```bash
gocactl secret bind add team-a/db-password \
  --namespace team-a --service-account eso-reader --auth-method my-cluster
```

### 3. The SecretStore

No token Secret to create — just name the ServiceAccount:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: goca
  namespace: team-a
spec:
  provider:
    goca:
      server: "https://goca.example.com"
      audience: "goca-csi"        # matches the trust domain's audience
      authMethod: "my-cluster"    # matches --auth-method below
      serviceAccountRef:
        name: eso-reader
      # caBundle: <base64 PEM>, or caProvider, if goca's cert isn't already trusted
```

### 4. The ExternalSecret

Identical to the webhook-provider example below — `secretStoreRef.kind:
SecretStore` is all that changes between the two paths. For a certificate
secret, one `dataFrom` entry syncs all three files at once (`tls.crt`,
`tls.key`, `ca.crt`) via `GetSecretMap`, instead of three `data[]` entries:

```yaml
spec:
  target:
    name: web-tls
    template: { type: kubernetes.io/tls }
  dataFrom:
    - extract:
        key: team-a/tls
```

### Getting the image

This provider isn't in an official ESO release. The `providers/v1/goca`
package (API types, provider client, registration file) currently lives
only as an uncommitted patch against a local clone of
[external-secrets/external-secrets](https://github.com/external-secrets/external-secrets)
v2.10.0 — it has not been pushed to a public fork yet. To build it:

1. Clone upstream and apply the goca provider (ask in-repo for the current
   patch, or re-derive it from `providers/v1/goca/goca.go` — it's one file
   of provider logic plus a one-line `pkg/register/goca.go`, both written
   against ESO's own `esv1.Provider`/`SecretsClient` conventions).
2. Build both the controller and admission-webhook binaries with the
   `goca` (or `all_providers`) build tag and the repo's own `Dockerfile`:

   ```bash
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
     go build -tags all_providers -o bin/external-secrets-linux-amd64 .
   docker build --platform linux/amd64 -t your-registry/external-secrets-goca:v2.10.0-goca .
   docker push your-registry/external-secrets-goca:v2.10.0-goca
   ```
3. Point **both** the `external-secrets` (controller) and
   `external-secrets-webhook` (admission validation) Deployments at the new
   image — the webhook validates `SecretStore.spec.provider` too, and
   without the goca provider compiled in it rejects a `goca:` block with
   `secret stores must only have exactly one backend specified, found 0`.

If you'd rather not maintain a fork long-term, consider opening a PR
upstream — the provider is self-contained and was written against ESO's
own conventions from the start.

## Generic webhook provider

Works with any official, unmodified ESO install — no custom image needed.
The trade-off is in how it authenticates.

### The one thing that's different from CSI, and why it matters

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

### Prerequisites

- A goca server with at least one CSI trust domain configured (`gocactl
  csi-auth list`) — see [step 0 of the CSI walkthrough](kubernetes/csi.md#0-enable-csi-on-the-goca-server)
  if you don't have one yet. ESO reuses the exact same trust domains.
- [External Secrets Operator](https://external-secrets.io) installed
  (`helm install external-secrets external-secrets/external-secrets -n
  external-secrets --create-namespace`).
- A secret already in goca, bound the same way you'd bind it for CSI.

### 1. Create the tenant namespace's identity

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

### 2. Bind the secret in goca

Exactly the CSI binding command, with `--auth-method` naming whichever trust
domain this cluster is registered as:

```bash
gocactl secret bind add team-a/db-password \
  --namespace team-a --service-account eso-reader --auth-method my-cluster
```

### 3. The token Secret and the SecretStore

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

### 4. The ExternalSecret

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

The native provider's `dataFrom`/`GetSecretMap` (see above) already fetches
all three files in one request. This section is the webhook-provider
equivalent: a `certificate`-type secret has three files (`tls.crt`,
`tls.key`, `ca.crt`), so `/api/v1/eso/secret` refuses to guess — omitting
`?property=` on a multi-file secret is a 400, not an arbitrary pick (unless
`?all=true` is set, which the webhook provider has no way to send). Add one
`data[]` entry per file, using `remoteRef.property`:

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

With `?all=true` (what the native provider's `GetSecretMap`/`dataFrom` sends)
the shape is different — every file at once, base64-encoded, `property` not
required:

```json
{
  "name": "team-a/tls",
  "version": "cert:0F3A...",
  "files": {"tls.crt": "...", "tls.key": "...", "ca.crt": "..."}
}
```

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
  `ClusterSecretStore` or a shared token (webhook provider), or your RBAC
  `Role` grants `serviceaccounts/token` more broadly than one `resourceNames`
  entry (native provider). Scope it back down.
- **Native provider: `goca: request a token for ServiceAccount ...: forbidden`**
  — the ESO controller's own ServiceAccount lacks the RBAC from step 1
  (`create` on `serviceaccounts/token`, scoped to that specific
  ServiceAccount). Check `kubectl auth can-i create
  serviceaccounts/token --as=system:serviceaccount:external-secrets:external-secrets
  -n team-a --subresource=token`.
- **Native provider: `no goca provider config found`** — the `SecretStore`
  wasn't picked up as a `goca` type. Confirm your ESO image was actually
  built with the provider included (`-tags all_providers` or `-tags goca`)
  and `kubectl get secretstore goca -n team-a -o yaml` shows `spec.provider.goca`.
