# goca + cert-manager demo

A minimal, copy-pasteable path from a running goca server to a Kubernetes
`Certificate` object holding a live certificate — no HTTP-01/DNS-01 challenge
propagation to wait on, since goca's ACME implementation is
[EAB-only](../ACME-EAB.md): the pre-shared key you create below *is* the
trust decision, and every authorization comes back already `"valid"`.

This directory is the "just make it work" version. For the full story —
scoping credentials, revocation, multi-cluster patterns, troubleshooting,
security model — see **[../ACME-EAB.md](../ACME-EAB.md)**, which this demo
follows exactly.

## Prerequisites

- A running goca server with at least one certificate authority, reachable
  from the cluster (`goca setup` + `goca ca create --wizard` if you haven't
  done that yet — see [../SETUP.md](../SETUP.md)).
- `kubectl` pointed at a cluster, with permission to install cluster-scoped
  resources (cert-manager's CRDs, a `ClusterIssuer`).
- `helm`, if you use the Helm install path below — optional, the plain
  manifest works too.

## 1. Install cert-manager (latest)

Either works; both install the current latest release, not a version pinned
in this file that would go stale.

**Plain manifest** (simplest, no other tooling required):

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
```

**Helm** (the path cert-manager's own docs recommend for anything beyond a
quick test):

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
    --namespace cert-manager --create-namespace \
    --set crds.enabled=true
```

Either way, wait for it to come up before continuing:

```bash
kubectl wait --for=condition=Ready pods --all --namespace cert-manager --timeout=180s
kubectl get pods --namespace cert-manager
```

You should see `cert-manager`, `cert-manager-cainjector` and
`cert-manager-webhook` all `Running`.

## 2. Create an EAB credential in goca

One credential per cluster (or per environment) is the recommended pattern —
scoped to the zone that cluster is allowed to request for, with
`--max-accounts 1` so the credential can only ever bootstrap the one
cert-manager instance you intend, even if the key leaks later:

```bash
goca acme eab create k8s-demo \
    --allowed-domain '*.svc.k8s-demo.internal' \
    --max-accounts 1
```

This prints a `keyID` and an HMAC key **once** — copy both now. If you lose
the key, delete the credential and create a new one; goca never stores it in
a form it can show you again.

```
key id:    6z9kx5d8vdnvqjeermc7
hmac key:  3tVcO2s_4dn2hUdjuzCk0axZVSXMjDaL9DTuyzG3K4o
```

## 3. Put the HMAC key in a Secret

Never commit the key to a file — create the Secret imperatively instead of
checking in a `secret.yaml`:

```bash
kubectl create secret generic goca-eab \
    --namespace cert-manager \
    --from-literal=hmac-key='<the HMAC key from step 2>'
```

## 4. Apply the ClusterIssuer

Edit [`cluster-issuer.yaml`](cluster-issuer.yaml): replace `CA_BASE_URL`
with your goca server's base URL (no scheme-relative shortcuts — the full
`https://ca.example.com`) and `EAB_KEY_ID` with the `keyID` from step 2.
Then:

```bash
kubectl apply -f cluster-issuer.yaml
kubectl get clusterissuer goca
```

Wait for `READY` to flip to `True`:

```bash
kubectl wait --for=condition=Ready clusterissuer/goca --timeout=60s
```

If it doesn't, `kubectl describe clusterissuer goca` — cert-manager surfaces
the directory-fetch or registration error directly there. Common causes:
the cluster can't reach `CA_BASE_URL` (check with a throwaway pod:
`kubectl run -it --rm debug --image=curlimages/curl -- curl -s https://CA_BASE_URL/acme/directory`),
or the `keyID`/Secret don't match what goca has on file
(`goca acme eab show k8s-demo`).

## 5. Request a certificate

Edit [`certificate.yaml`](certificate.yaml) if you want a different DNS
name than `app.svc.k8s-demo.internal` — whatever you put in `dnsNames` must
match the EAB credential's `--allowed-domain` pattern from step 2, or goca
rejects the order. Then:

```bash
kubectl apply -f certificate.yaml
kubectl wait --for=condition=Ready certificate/app-tls --timeout=60s
kubectl get certificate app-tls
```

`READY` should go `True` within a few seconds — there's no challenge
propagation delay here, goca signs the order as soon as it's finalized.

## 6. Look at what you got

```bash
kubectl get secret app-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -text
```

It's an entirely ordinary goca certificate from here on — searchable,
renewable, revocable from the CLI, API or portal, exactly like one issued
any other way. Find it with:

```bash
goca cert list --query 'acme:k8s-demo'
```

cert-manager renews it automatically before `renewBefore` (see
`certificate.yaml`); you don't need to do anything for routine renewal.

## Cleanup

```bash
kubectl delete -f certificate.yaml
kubectl delete -f cluster-issuer.yaml
kubectl delete secret goca-eab --namespace cert-manager
goca acme eab delete k8s-demo --yes   # only works once no accounts reference it
```

Uninstalling cert-manager itself, if this was a throwaway test cluster:

```bash
helm uninstall cert-manager --namespace cert-manager   # if installed via Helm
# or
kubectl delete -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
```

## Troubleshooting

See **[../ACME-EAB.md#troubleshooting](../ACME-EAB.md#troubleshooting)** —
it covers `externalAccountRequired`, `rejectedIdentifier`, `badCSR`, orders
stuck at `pending`, and `ClusterIssuer: Ready: False` in more depth than
duplicated here.

## Related: mounting secrets directly with the CSI driver

This demo gets a certificate into Kubernetes as a `Secret`, via ACME. If you
want to mount a goca secret — including a certificate — straight into a
pod as files, with nothing ever written to etcd, see
**[csi/README.md](csi/README.md)** instead: it walks through goca's
Secrets Store CSI Driver provider.
