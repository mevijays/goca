# goca + Secrets Store CSI Driver demo

Mounts a goca secret - a plain key/value password and a goca-issued
certificate - as files in a pod, with no Kubernetes `Secret` object holding
the plaintext anywhere in etcd (unless you opt into that via
`secretObjects`, which this demo doesn't).

**How it works, in one sentence:** kubelet asks the upstream CSI driver to
mount a volume, the driver asks `goca run csi-provider` (one pod per node)
over a Unix socket, and that provider forwards the *pod's own*
ServiceAccount token to the central goca server, which is the only thing
that ever authenticates the token, checks it against a secret's bindings,
and decrypts anything - see `internal/csi`'s package doc comment for the
full reasoning, and `internal/pqcrypt`'s for how a secret is sealed at rest
in the first place.

## Prerequisites

- A running goca server with `csi.enabled: true` configured (see
  [step 0](#0-enable-csi-on-the-goca-server) below) and at least one secret
  to mount.
- `kubectl` pointed at a cluster, with permission to install cluster-scoped
  resources (the driver's CRDs, a `CSIDriver`, RBAC).
- Whether your cluster's ServiceAccount issuer is publicly resolvable
  decides which of `csi.issuer_url` or `csi.api_server_url` you configure -
  see the note in step 0.

## 0. Enable CSI on the goca server

Add to `config.yaml` (or hand-edit an existing one) and restart `goca run
web`:

```yaml
csi:
  enabled: true
  audience: goca-csi

  # Path A - your cluster's ServiceAccount issuer is publicly reachable
  # (EKS, GKE, AKS, or any cluster started with a public
  # --service-account-issuer). No TokenReview credentials needed.
  issuer_url: https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE

  # Path B - it isn't (kind, most on-prem clusters): leave issuer_url empty
  # and fill these in instead. reviewer_token belongs to a ServiceAccount
  # bound to system:auth-delegator - rbac.yaml creates one for you
  # (goca-server-token-reviewer); get its token with:
  #   kubectl create token goca-server-token-reviewer -n goca-csi --duration=8760h
  # api_server_url: https://<your api server host>:6443
  # ca_cert: |
  #   -----BEGIN CERTIFICATE-----
  #   ...
  # reviewer_token: eyJhbGciOi...
```

Both paths can be set together - `issuer_url` is tried first, `api_server_url`
is the fallback whenever it's unreachable. See `CSIConfig` in
`internal/config/config.go` for every field.

## 1. Install the Secrets Store CSI Driver (latest, upstream)

```bash
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm repo update
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
    --namespace kube-system \
    --set syncSecret.enabled=false \
    --set enableSecretRotation=true
```

`syncSecret.enabled=false` is intentional - this demo mounts files directly,
never syncing into a Kubernetes `Secret`. `enableSecretRotation=true` is
what makes writing a new version of a secret in goca show up in an already-
running pod within `rotationPollInterval` (default 2m), no pod restart
needed.

```bash
kubectl wait --for=condition=Ready pods --all --namespace kube-system \
    --selector app=secrets-store-csi-driver --timeout=180s
```

## 2. Install the goca provider

```bash
kubectl apply -f rbac.yaml
```

Register goca's token audience on the driver's own `CSIDriver` object - see
[`csidriver.yaml`](csidriver.yaml) for why this is a patch, not a separate
object:

```bash
kubectl patch csidriver secrets-store.csi.k8s.io --type merge -p \
    '{"spec":{"tokenRequests":[{"audience":"goca-csi","expirationSeconds":3600}]}}'
```

Edit [`provider-daemonset.yaml`](provider-daemonset.yaml): replace
`GOCA_BASE_URL` with your goca server's base URL. If its TLS certificate
isn't from a CA your nodes already trust, uncomment the `--ca-cert` flag and
CA-bundle volume, and create that ConfigMap first:

```bash
kubectl create configmap goca-ca-bundle --namespace goca-csi \
    --from-file=ca.crt=<path to your goca root CA chain>
```

Then:

```bash
kubectl apply -f provider-daemonset.yaml
kubectl wait --for=condition=Ready pods --all --namespace goca-csi --timeout=120s
kubectl logs -n goca-csi -l app=goca-csi-provider
```

You should see `"goca csi provider listening"` for each node.

## 3. Create secrets in goca and bind them

```bash
goca secret create demo/db/password
goca secret put demo/db/password 'hunter2'
goca secret bind add demo/db/password --namespace default --service-account demo-app

goca secret create demo/web-tls --type certificate --cert <a certificate id or serial>
goca secret bind add demo/web-tls --namespace default --service-account demo-app
```

Binding is the entire authorization decision - only a pod running as the
bound (namespace, ServiceAccount) pair can fetch a secret, glob-matched
(`web-*`, `*`), regardless of what a `SecretProviderClass` in that namespace
claims to want.

## 4. Apply the SecretProviderClasses and the demo pod

Edit [`secretproviderclass.yaml`](secretproviderclass.yaml) if you changed
the secret names above (or want to drop the `gocaAddress` parameter and rely
on the provider's own `--goca-address` default). Then:

```bash
kubectl apply -f secretproviderclass.yaml
kubectl apply -f pod.yaml
kubectl wait --for=condition=Ready pod/demo-app --timeout=60s
```

## 5. Look at what got mounted

```bash
kubectl exec demo-app -- cat /mnt/secrets/db/db-password
kubectl exec demo-app -- ls -la /mnt/secrets/tls
kubectl exec demo-app -- cat /mnt/secrets/tls/server.crt
```

`db-password` holds the plaintext value; `server.crt`/`server.key`/`ca.crt`
are the certificate's full chain, private key, and issuer chain
respectively (the `items` mapping in `secretproviderclass.yaml` renamed the
provider's default `tls.crt`/`tls.key`/`ca.crt` to these).

## 6. See rotation happen

```bash
goca secret put demo/db/password 'new-value-123'
```

Within `rotationPollInterval` (2 minutes by default), the driver notices the
version changed and re-runs Mount:

```bash
kubectl exec demo-app -- cat /mnt/secrets/db/db-password   # eventually: new-value-123
```

## 7. Confirm the binding is actually enforced

Try mounting `demo/db/password` from a pod running as a *different*
ServiceAccount you never bound - it should fail to mount with a "not found
or not authorized" error surfaced by `kubectl describe pod`, proving the
binding (not just knowledge of the secret's name) is the real access
control:

```bash
kubectl create serviceaccount other-app
kubectl run other-app --image=busybox --serviceaccount=other-app \
    --overrides='{"spec":{"containers":[{"name":"app","image":"busybox","command":["sleep","infinity"],"volumeMounts":[{"name":"db-password","mountPath":"/mnt"}]}],"volumes":[{"name":"db-password","csi":{"driver":"secrets-store.csi.k8s.io","volumeAttributes":{"secretProviderClass":"goca-db-password"}}}]}}'
kubectl describe pod other-app   # Events: MountVolume.SetUp failed ... not found or not authorized
kubectl delete pod/other-app serviceaccount/other-app
```

## Cleanup

```bash
kubectl delete -f pod.yaml
kubectl delete -f secretproviderclass.yaml
kubectl delete -f provider-daemonset.yaml
kubectl delete -f rbac.yaml
# leaves the goca-csi tokenRequests entry on the shared CSIDriver object -
# harmless, but to remove it: kubectl patch csidriver secrets-store.csi.k8s.io --type json -p '[{"op":"remove","path":"/spec/tokenRequests"}]'
goca secret rm demo/db/password --yes
goca secret rm demo/web-tls --yes
helm uninstall csi-secrets-store --namespace kube-system
```

## Troubleshooting

- **`kubectl describe pod` shows `MountVolume.SetUp failed ... rpc error`**
  - The error text from the provider is surfaced verbatim. `not found or
    not authorized` means the secret doesn't exist or isn't bound to this
    (namespace, ServiceAccount) - check `goca secret bind list <name>`.
  - A network/TLS error reaching goca means `--goca-address`/`gocaAddress`
    or `--ca-cert` is wrong; test from the provider pod:
    `kubectl exec -n goca-csi <pod> -- wget -qO- --no-check-certificate https://GOCA_BASE_URL/healthz`
    (the container has no shell, but the driver's sidecar image does if you
    need a fuller debug session - `kubectl debug`).
- **Provider logs `no token was issued for audience "goca-csi"`** - the
  `CSIDriver` object's `tokenRequests[].audience` doesn't match `--audience`
  on the provider or `csi.audience` on the server. All three must agree.
- **Server logs `k8sauth: OIDC issuer unreachable and no TokenReview
  fallback is configured`** - set at least one of `csi.issuer_url` /
  `csi.api_server_url` (step 0).
- **`system:auth-delegator` errors from TokenReview** - the reviewer
  ServiceAccount's token in `csi.reviewer_token` doesn't have the
  `ClusterRoleBinding` from `rbac.yaml` applied, or the token has expired
  (they're not permanent by default - reissue with a longer `--duration` or
  automate renewal).

See [../README.md](../README.md) for the cert-manager/ACME demo this
complements - that one gets a certificate into Kubernetes as a `Secret` via
ACME; this one mounts any goca secret, including a certificate, as files
without ever putting it in etcd.
