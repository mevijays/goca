# syntax=docker/dockerfile:1
#
# goca ships as one static, CGO-free Go binary (the SQLite driver is
# modernc.org/sqlite, pure Go), so the runtime image needs nothing but the
# binary itself, a CA trust bundle for outbound TLS (LDAPS, an external CA's
# API), and a place to keep its data.
#
# Build:
#   docker build -t goca .
#   docker build --build-arg VERSION=v1.2.3 -t goca:v1.2.3 .
#
# Run (first time, to generate config + the local admin account):
#   docker run --rm -it -v goca-data:/data ghcr.io/mevijays/goca:latest \
#     setup --data-dir /data --out /data/config.yaml --port 8080
#
# Run (day to day - GOCA_CONFIG below is already set, so no --config needed):
#   docker run -d --name goca -p 8080:8080 -v goca-data:/data ghcr.io/mevijays/goca:latest
#
# The image also carries gocactl, the remote client, so a workstation or a CI
# job can administer a goca server without installing anything:
#   docker run --rm -it --entrypoint gocactl ghcr.io/mevijays/goca:latest \
#     --server https://ca.example.com --token "$GOCA_TOKEN" ca list

########## build ##########
# --platform=$BUILDPLATFORM pins this stage to the host architecture even
# when building a foreign target (e.g. arm64 on an amd64 runner): with
# CGO_ENABLED=0, Go cross-compiles natively via GOOS/GOARCH below, so the
# compiler itself never runs under QEMU emulation - only the tiny final
# COPY-only stage targets the real platform, and that needs no emulation
# either since nothing executes in it.
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS build

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath \
      -ldflags "-s -w \
        -X github.com/mevijays/goca/internal/cli.Version=${VERSION} \
        -X github.com/mevijays/goca/internal/cli.Commit=${COMMIT} \
        -X github.com/mevijays/goca/internal/cli.Date=${DATE}" \
      -o /out/goca .

# gocactl is built from the same tree and shipped alongside, so the client is
# always the exact version of the server it came with. It has its own ldflag
# path because internal/rcli carries its own build stamp.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath \
      -ldflags "-s -w \
        -X github.com/mevijays/goca/internal/rcli.Version=${VERSION} \
        -X github.com/mevijays/goca/internal/rcli.Commit=${COMMIT} \
        -X github.com/mevijays/goca/internal/rcli.Date=${DATE}" \
      -o /out/gocactl ./cmd/gocactl

# The data directory is created here (this stage has a shell) and copied into
# the runtime stage with the correct ownership, since a Docker VOLUME
# inherits whatever the image already has at that path - distroless has no
# shell to chown it after the fact.
RUN mkdir -p /data && chown 65532:65532 /data

########## runtime ##########
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="goca" \
      org.opencontainers.image.description="Self-hosted certificate authority: CLI, REST API and web portal in one binary" \
      org.opencontainers.image.source="https://github.com/mevijays/goca" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/goca /usr/local/bin/goca
COPY --from=build /out/gocactl /usr/local/bin/gocactl
COPY --from=build --chown=65532:65532 /data /data

# Config discovery finds this without any flag; `goca setup` still needs
# --data-dir/--out pointed at /data on first run (see the usage note above).
ENV GOCA_CONFIG=/data/config.yaml

VOLUME ["/data"]
EXPOSE 8080

# distroless:nonroot already runs as uid/gid 65532; set explicitly so it's
# correct even if a future base image changes its default.
USER 65532:65532
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/goca"]
CMD ["run", "web"]
