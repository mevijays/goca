# goca's native External Secrets Operator provider

This directory holds everything needed to build an [External Secrets
Operator](https://external-secrets.io) image with goca's native provider
(`providers/v1/goca` in ESO's tree) compiled in - see
[`docs/eso.md`](../../docs/eso.md) for what the provider does and why it
exists (short version: it mints a fresh Kubernetes `TokenRequest` token per
fetch for a named ServiceAccount, the same mechanism CSI uses, instead of a
static Secret you have to rotate by hand).

The provider isn't in an official ESO release, and this repo doesn't carry a
full fork of `external-secrets/external-secrets` (that's ~2,000 files of
someone else's project). Instead:

- **`overlay/`** - the goca-specific files, as full copies, laid out to
  mirror their path inside the ESO tree: one new provider package
  (`providers/v1/goca/`), one new API type
  (`apis/externalsecrets/v1/secretstore_goca_types.go`), the two upstream
  files that had to change to reference it (`secretstore_types.go` and its
  generated `zz_generated.deepcopy.go`), and the one-file registration hook
  (`pkg/register/goca.go`).
- **`ESO_REF`** - the upstream tag these files were written and tested
  against (currently `v2.10.0`). Everything here is pinned to it; the
  Dockerfile clones exactly this tag before overlaying.
- **`Dockerfile`** - clones upstream at `ESO_REF`, copies `overlay/` on top,
  and builds with upstream's own `all_providers` tag (their default -
  `pkg/register/goca.go` is gated on `goca || all_providers`, so this is the
  same mechanism every other provider uses).
- **`crds/`** - the regenerated `SecretStore`/`ClusterSecretStore` CRDs
  (upstream's `config/crds/bases/*.yaml` and `deploy/crds/bundle.yaml`) with
  the `provider.goca` field present, for `kubectl apply --server-side
  --force-conflicts` (they exceed the plain-`apply` annotation size limit).
  Not used by the Docker build - CRDs are a cluster-side concern, not
  something baked into the image.

## CI

`.github/workflows/release.yml`'s `eso-operator` job builds and pushes this
image to `ghcr.io/mevijays/external-secrets-goca` on every goca release tag,
alongside the `goca`/`gocactl` binaries and the `goca` server image. Both
roles ESO needs - the controller and the admission webhook - run this same
image; the webhook also validates `SecretStore` specs, and without the goca
provider compiled in it rejects a `goca:` block
(`secret stores must only have exactly one backend specified, found 0`).

## Bumping `ESO_REF`

There's no codegen step in CI - `zz_generated.deepcopy.go` here is a static,
already-regenerated file, checked in like the rest of `overlay/`. When
upstream ships a new version worth tracking:

1. Clone `external-secrets/external-secrets` at the new tag.
2. Copy `overlay/providers/v1/goca/`, `overlay/pkg/register/goca.go`, and
   `overlay/apis/externalsecrets/v1/secretstore_goca_types.go` in as-is (or
   diff against the previous `ESO_REF` first, in case ESO's own interfaces
   moved).
3. Re-apply the one-field addition to `secretstore_types.go` (see the `Goca
   *GocaProvider` field next to `Webhook` in `SecretStoreProvider`).
4. Run `make generate` in the clone (needs `controller-gen`; `yq` via `brew
   install yq` if missing) and copy the regenerated
   `zz_generated.deepcopy.go` and the three files under `crds/` back here.
5. Update `ESO_REF`, run `go build ./...` and `go test
   ./providers/v1/goca/... -race` in the clone to confirm, then commit.

## Building and testing locally

```bash
docker build -f integrations/eso-provider/Dockerfile \
  --build-arg ESO_REF="$(cat integrations/eso-provider/ESO_REF)" \
  -t external-secrets-goca:local .
```
