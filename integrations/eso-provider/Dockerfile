# syntax=docker/dockerfile:1
#
# Builds External Secrets Operator (upstream external-secrets/external-secrets,
# pinned by ESO_REF) with goca's native provider compiled in via ESO's own
# `all_providers` build tag. See docs/eso.md in this repo for what the
# provider does and why it exists, and README.md in this directory for how
# the overlay/ files here were produced and how to bump ESO_REF.
#
# This one image serves both roles ESO needs: the controller and the
# admission webhook are the same binary (`external-secrets`, different
# subcommands) - both need the goca provider compiled in, since the webhook
# also validates SecretStore specs and rejects an unrecognised `goca:` block
# otherwise.
#
# Build:
#   docker build -f integrations/eso-provider/Dockerfile \
#     --build-arg ESO_REF=$(cat integrations/eso-provider/ESO_REF) \
#     -t external-secrets-goca:v2.10.0-goca .
#
# Build context is the repo root (needs integrations/eso-provider/overlay/).

########## build ##########
# --platform=$BUILDPLATFORM pins this stage to the host architecture even
# when building a foreign target: with CGO_ENABLED=0, Go cross-compiles
# natively via GOOS/GOARCH below, so the compiler never runs under QEMU -
# only the tiny final COPY-only stage targets the real platform, and that
# needs no emulation either since nothing executes in it. Mirrors this
# repo's own Dockerfile.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

RUN apk add --no-cache git ca-certificates

ARG ESO_REF=v2.10.0
WORKDIR /src
RUN git clone --depth 1 --branch "${ESO_REF}" \
      https://github.com/external-secrets/external-secrets.git .

# Overlay goca's provider onto the pinned upstream checkout: one new
# provider package, one new API type, one field added to SecretStoreProvider
# (secretstore_types.go and its regenerated deepcopy), one registration file.
COPY integrations/eso-provider/overlay/ /src/

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

# all_providers is upstream's own default build tag (see their Makefile,
# PROVIDER ?= all_providers) - every official provider plus, now, goca's
# (pkg/register/goca.go is gated on `goca || all_providers`).
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags all_providers -trimpath -ldflags="-s -w" \
      -o /out/external-secrets .

########## runtime ##########
# Same distroless base upstream's own Dockerfile uses.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="external-secrets-goca" \
      org.opencontainers.image.description="External Secrets Operator (upstream) with goca's native TokenRequest-based provider compiled in" \
      org.opencontainers.image.source="https://github.com/mevijays/goca" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/external-secrets /bin/external-secrets

USER 65532:65532
ENTRYPOINT ["/bin/external-secrets"]
