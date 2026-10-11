# High availability on Kubernetes

goca runs on Kubernetes as **several identical, stateless replicas sharing one
PostgreSQL database**. There is no leader, no replica-to-replica traffic and
no consensus protocol inside goca: every pod can serve every request, and all
state — certificates, keys, secrets, ACME accounts and nonces, sessions,
sign-in throttling, the webhook queue — lives in PostgreSQL. You scale by
changing the replica count and get high availability for the database from
PostgreSQL itself (we recommend [CloudNativePG](https://cloudnative-pg.io/)).

```
                     Service (kube-proxy spreads requests)
             ┌────────────────────┼────────────────────┐
         goca pod             goca pod             goca pod      ← stateless, any can serve anything
             └────────────────────┼────────────────────┘
                                  │
                   PostgreSQL (CloudNativePG: primary + standbys,
                               automatic failover)
```

!!! danger "PostgreSQL only"
    On Kubernetes goca runs on PostgreSQL, even with a single replica. SQLite
    is one file; several pods writing it — or a later scale-up — corrupts it.
    The Helm chart refuses to render with any other `database.driver`.

## Why not Raft inside goca?

Raft (or any consensus log embedded in goca) was considered and rejected:

- **It would rebuild a replicated database inside a CA.** Every write would
  have to become a deterministic log entry, plus snapshots, membership changes,
  quorum loss recovery, backup/restore and a StatefulSet with stable identities
  — a large new failure surface in the component that holds signing keys.
- **PostgreSQL already does this, and you already run it.** goca's state is
  relational and transactional; the correctness properties a CA needs
  (strictly increasing CRL numbers, single issuance per ACME order, exactly-once
  webhook delivery, single-use nonces) map directly onto atomic SQL statements.
  CloudNativePG provides replication and automatic failover, so goca inherits HA
  without implementing any of it.
- **Stateless replicas are operationally simpler**: rolling updates, HPA,
  PodDisruptionBudgets and node failures all work the ordinary Kubernetes way.

Raft would only earn its keep for a cluster with *no* external database at
all. That is not a mode goca supports for HA.

## What makes the replicas safe to run together

goca was originally a single process. These are the places that assumed it,
and how each now works — every one was reproduced as a failure before being
fixed (see `internal/web/replicas_test.go` and
`internal/store/cluster_safety_test.go`):

| Concern | Before | Now |
|---|---|---|
| ACME nonces | per-process map — a nonce from pod A was `badNonce` at pod B; under round-robin, ACME never completed | shared table; redemption is one conditional `DELETE`, so exactly one replica can redeem a nonce |
| Sign-in throttling | per-process counters — N replicas allowed N× the failures | counted in the database |
| CSI trust-domain cache | invalidated only on the replica that served the change — a *disabled* domain kept working on the others | each request re-reads the row; verifier rebuilt when its fingerprint changes |
| Webhook delivery | claim race — 200 of 300 deliveries claimed by several replicas | `FOR UPDATE SKIP LOCKED` claim; no double delivery, no deadlocks |
| CRL numbers | read-then-write — the same CRL number reused for different CRLs | one atomic `UPDATE … RETURNING` |
| Secret versions | concurrent writes failed on the unique constraint | atomic version reservation |
| Schema setup | replicas starting together raced `CREATE TABLE` — most crashed | runs under a PostgreSQL advisory lock |
| First admin user | concurrent startups failed creating it | the loser of the race refreshes instead |

Background work needs no leader: the hourly janitor only deletes expired rows
(idempotent), and webhook delivery claims its rows.

## Install

### 1. PostgreSQL

Use an HA PostgreSQL. With CloudNativePG:

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: goca-db
  namespace: goca
spec:
  instances: 3
  storage: {size: 5Gi}
  bootstrap:
    initdb: {database: goca, owner: goca}
```

CloudNativePG creates a `goca-db-app` Secret with the password and a
`goca-db-rw` Service that always points at the current primary — use that
Service as goca's database host.

### 2. Generate goca's config

`goca setup` writes `config.yaml` (including the master key that seals every
private key and secret) and initializes the database, so it needs to reach
PostgreSQL once — a port-forward is enough:

```bash
kubectl -n goca port-forward svc/goca-db-rw 15432:5432 &

goca setup --non-interactive \
  --database-driver postgres --db-host 127.0.0.1 --db-port 15432 \
  --db-name goca --db-user goca --db-password "$(kubectl -n goca get secret goca-db-app -o jsonpath='{.data.password}' | base64 -d)" \
  --db-sslmode require \
  --admin-user admin --port 8080 --base-url https://goca.example.com \
  --data-dir ./goca-setup --out ./goca-setup/config.yaml
```

Then point the config at the in-cluster address and the pod's scratch
directory before storing it:

```yaml
data_dir: /data
database:
  host: goca-db-rw.goca.svc   # was 127.0.0.1
  port: 5432                  # was 15432
```

```bash
kubectl -n goca create secret generic goca-config --from-file=config.yaml=./goca-setup/config.yaml
```

`server.base_url` must be the URL clients actually use — ACME directory URLs
are built from it.

### 3. Install the chart

```bash
helm install goca deploy/helm/goca -n goca \
  --set image.repository=ghcr.io/mevijays/goca \
  --set image.tag=<release>        # a goca release containing the HA work
```

The chart's defaults: 3 replicas spread across nodes, a PodDisruptionBudget
(`maxUnavailable: 1`), rolling updates that never drop below the full count
(`maxUnavailable: 0`), a read-only root filesystem running as non-root, and:

| Probe | Path | Meaning |
|---|---|---|
| startup | `/livez` | generous — a starting pod may wait for the schema lock |
| liveness | `/livez` | process health only; never the database, so a database blip can't restart every replica |
| readiness | `/readyz` | database reachable; an unready pod is removed from the Service |

A `preStop` sleep keeps a terminating pod serving until the Service has stopped
routing to it.

## Verified on a real cluster

The chart was installed with 3 replicas on a 4-node cluster (Ceph storage)
against a fresh database, and exercised from inside the cluster through the
Service with keep-alives disabled, so kube-proxy spread requests across pods
(per-pod logs confirmed: ACME requests 11/10/14, sign-ins 3/5/1):

| Scenario | Result |
|---|---|
| 3 replicas starting together on an empty database | all Ready, 0 restarts, schema and admin created once |
| 5 complete ACME flows across replicas | pass, 0 `badNonce` |
| sign-in throttle across replicas | 5× 401 then 429 |
| 2 pods deleted during 90 s of continuous ACME load | 838 flows, **0 failed** |
| rolling restart of all replicas under load | 926 flows, **0 failed** (rollout took 9 s) |
| pod force-killed (no grace period) under load | 549 flows, 0 failed in this run¹ |
| PostgreSQL restarted | goca pods went unready, **0 restarts**, all Ready again 5 s after the database |

¹ A request in flight at the instant a pod crashes can still fail — no
server can finish a request it is no longer running. ACME clients, cert-manager
included, retry; the point is that a crash costs nothing beyond that request.

## Operations

- **Scaling** — `helm upgrade … --set replicaCount=5`, or enable
  `autoscaling` in the values.
- **Upgrades** — `helm upgrade` rolls one pod at a time. Schema migrations are
  additive and run under the advisory lock, so old and new replicas can serve
  side by side during the rollout.
- **Backups** — back up PostgreSQL (CloudNativePG supports scheduled and
  point-in-time backups) **and** the `goca-config` Secret: the database is
  useless without the master key in it, and vice versa.
- **The CSI provider** (`goca run csi-provider`, a DaemonSet) and the ESO
  provider talk to goca over HTTP, so they simply point at the goca Service.
