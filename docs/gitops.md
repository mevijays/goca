# GitOps for secrets

goca's secret manager is designed to be driven from git. The pieces:

- **`gocactl apply -f secrets.yaml`** — declarative, idempotent create/update of
  secrets and their CSI bindings.
- **`gocactl diff -f secrets.yaml`** — drift detection for CI gates (exit 1 on
  drift, exit 2 on error).
- **SecretProviderClass** — a plain Kubernetes object, so ArgoCD (or Flux)
  applies it the way it applies everything else.

Together these close the loop: git is the source of truth for *which secrets
exist, what they are called, and who may mount them*; a pipeline is the source
of *values*; ArgoCD is the source of truth for *the Kubernetes side*.

## What goes in git, and what doesn't

| In git | Not in git |
| --- | --- |
| Secret **names**, types, descriptions, labels, rotation policy | Secret **values** (passwords, keys, file contents) |
| CSI **bindings** (namespace / ServiceAccount / trust domain) | API tokens, master key, anything that decrypts |
| **SecretProviderClass** manifests | |

The split is deliberate. A manifest that declares `db-password` with a binding
for `prod/app` is safe to commit, review, and audit — it says nothing about
what the password *is*. The value is pushed by a pipeline that holds the
plaintext only transiently:

```
  git (manifests)                pipeline (values)
  ┌─────────────────────┐        ┌──────────────────────────────┐
  │ secrets.yaml        │        │ checkout → read value from    │
  │   db-password (kv)  │        │   vault/1Password/env →       │
  │   bindings: prod/app│        │   gocactl secret put          │
  │ spc.yaml            │        │     (plaintext never lands    │
  └─────────┬───────────┘        │    on disk or in git)         │
            │                    └──────────────┬───────────────┘
            ▼                                   ▼
  CI job on merge:                    goca server
  gocactl apply -f secrets.yaml   ┌─────────────────────┐
  gocactl diff -f secrets.yaml    │ db-password v42     │
  (gate: fail on drift)           │ binding prod/app    │
                                  └─────────────────────┘
```

## The manifest

```yaml
apiVersion: goca.dev/v1
kind: SecretManifest
secrets:
  - name: db-password
    type: kv                 # kv | file (certificate secrets are managed imperatively)
    description: primary db
    labels:
      team: platform
    rotationDays: 30
    bindings:
      - namespace: prod
        serviceAccount: app
        authMethod: cluster-a   # CSI trust domain; omit for "*" (any)
        expiresInDays: 7        # optional
      - namespace: "*"
        serviceAccount: "*"

  - name: api-key
    type: kv
    bindings:
      - namespace: staging
        serviceAccount: worker
```

Rules the parser enforces:

- `apiVersion`, when present, must be `goca.dev/v1`. A bare list of secrets
  (no wrapper) is accepted as a convenience.
- Secret names must be unique; `type` must be `kv` or `file`. **Certificate
  secrets are rejected** — they track a live certificate and are managed
  imperatively (`gocactl secret put --cert ...`).
- Binding fields are shell-glob patterns; an empty field means `*`.
- Duplicate `(namespace, serviceAccount, authMethod)` triples within one
  secret are an error.
- Multiple `-f` files are merged and validated together, so a name declared in
  two files is caught.

## apply

```
gocactl apply -f secrets.yaml            # converge
gocactl apply -f secrets.yaml --prune    # also remove undeclared bindings
gocactl apply -f secrets.yaml --dry-run  # show, don't change
```

For each declared secret, `apply` converges the server to the manifest:

| Situation | Action |
| --- | --- |
| Secret missing on server | create it, then create all declared bindings |
| `type` differs | **CONFLICT** — reported, never changed (type is immutable) |
| description / labels / rotationDays differ | update the changed fields |
| Declared binding missing | create it |
| Undeclared binding present | remove it **only with `--prune`** |

`apply` is idempotent: running it twice in a row, the second run is a no-op.
It **never deletes a secret** — removing a secret is a deliberate,
out-of-band act (`gocactl secret delete`), because deleting a secret destroys
its versions and any workload mounting it breaks.

## diff (the CI gate)

```
gocactl diff -f secrets.yaml             # exit 0 = in sync, exit 1 = drift
gocactl diff -f secrets.yaml --prune     # also report bindings that would be pruned
```

`diff` prints exactly what `apply` would do and changes nothing. The exit
codes are the contract a CI job relies on:

- **0** — server matches the manifest.
- **1** — drift detected (the plan is printed).
- **2** — something is broken (bad manifest, unreachable server, bad token).

That distinction matters: a CI gate that fails on "drift" should not look the
same as one that fails on "the token expired".

## The ArgoCD pattern

The full workflow has two reconcilers, each owning one side of the system:

```
                    ┌────────────────────────────────────────────┐
                    │                git repository              │
                    │  secrets/                                  │
                    │    secrets.yaml        (goca-side state)   │
                    │    spc.yaml            (k8s-side state)    │
                    └──────────┬─────────────────────┬───────────┘
                               │                     │
              on merge         │                     │  continuously
              (CI job)         ▼                     ▼
                    ┌──────────────────┐   ┌──────────────────────┐
                    │ gocactl apply    │   │ ArgoCD               │
                    │ gocactl diff     │   │ applies spc.yaml     │
                    │ (gate on drift)  │   │ to the cluster       │
                    └────────┬─────────┘   └──────────┬───────────┘
                             │ REST API               │ k8s API
                             ▼                        ▼
                    ┌──────────────────┐   ┌──────────────────────┐
                    │ goca server      │   │ cluster              │
                    │ secrets +        │◄──┤ SecretProviderClass  │
                    │ bindings         │   │ → CSI provider →     │
                    │                  │   │   pod mounts secret  │
                    └──────────────────┘   └──────────────────────┘
```

**ArgoCD owns the Kubernetes side.** The `SecretProviderClass` is an ordinary
k8s object. Commit it, ArgoCD applies it, and its normal drift detection and
self-healing cover it — no goca involvement.

**A CI job owns the goca side.** On merge (or on a schedule), a job runs:

```yaml
# .github/workflows/goca-secrets.yml
jobs:
  goca-secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.24' }
      - run: go build -o gocactl github.com/mevijays/goca/cmd/gocactl
      - name: Gate on drift
        env:
          GOCACTL_SERVER: ${{ secrets.GOCA_SERVER }}
          GOCACTL_TOKEN:  ${{ secrets.GOCA_TOKEN }}
        run: ./gocactl diff -f secrets/secrets.yaml --prune
      - name: Apply
        if: always()   # or: only on the default branch
        env:
          GOCACTL_SERVER: ${{ secrets.GOCA_SERVER }}
          GOCACTL_TOKEN:  ${{ secrets.GOCA_TOKEN }}
        run: ./gocactl apply -f secrets/secrets.yaml --prune
```

Notes on the job:

- `GOCACTL_TOKEN` is a **scoped, expiring, revocable** API token
  (`goca token create ci --role admin --days 90`), not a password and not the
  master key. Rotate it on a schedule; revoke it from the server if it leaks.
- Run `diff` first so a drift failure shows *what* drifted before the job
  fails. On the default branch, `apply` then converges it; on a PR, `diff`
  alone is the review gate ("this PR would change these bindings").
- `--prune` makes the manifest the complete source of truth for bindings.
  Without it, `apply` only adds and updates — a binding removed from git
  stays on the server until someone deletes it by hand. Pick one policy and
  be consistent; `--prune` is the stricter, more GitOps-faithful one.
- A **scheduled** run of `diff` (e.g. nightly) catches out-of-band changes —
  someone who created a binding from the web portal — and pages you instead
  of letting the drift accumulate.

**Values still come from the pipeline.** `apply` creates the secret's
*metadata*; the first *value* is pushed separately, by whatever system already
holds it:

```
gocactl secret put db-password --from-file /tmp/value   # pipeline, transient
```

After that, the manifest and the value live independently: the manifest
controls identity and access, the pipeline controls content and rotation.

## Why not a CRD?

The obvious alternative is a `GocaSecret` CRD plus an operator that watches
the cluster and reconciles goca. That is more moving parts: an operator to
deploy, upgrade, and secure in every cluster, with a credential to goca in
each one. The CI-job pattern gets the same guarantee — "git and goca agree" —
with one token, one job, and no per-cluster software. The CRD is the right
answer if you want the secret's *lifecycle* (creation, rotation, deletion) to
be a first-class Kubernetes object with its own status; until then, the
manifest plus a CI job is the smaller system that does the job.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `diff` exits 2 with `not signed in` | `GOCACTL_TOKEN` unset or wrong; the job needs the env var, not a local login |
| `diff` exits 1 forever on `labels` | Old client: nil-vs-empty label maps were compared as different. Rebuild `gocactl` from current source |
| `CONFLICT: type is ...` | The secret was created with a different type. Type is immutable — delete and recreate, or fix the manifest to match |
| Binding keeps coming back after removal | `apply` was run without `--prune`; the manifest no longer declares it but nothing removes it |
| `apply` succeeds but the pod can't mount | The goca side converged; check the k8s side — the `SecretProviderClass` (ArgoCD's job), the provider's `--auth-method`, and the binding's trust domain |