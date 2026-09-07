// This file exists only to mark a Go module boundary: it stops `go build
// ./...`, `go vet ./...`, etc. at the goca-lab repo root from trying to
// compile everything under overlay/, which belongs to a different module
// (github.com/external-secrets/external-secrets) and only ever compiles
// once copied onto a real checkout of that module - see README.md.
//
// Deliberately placed one level above overlay/, not inside it: the
// Dockerfile's `COPY integrations/eso-provider/overlay/ /src/` copies only
// the overlay/ subtree, so this file is never copied over ESO's own go.mod.
module github.com/mevijays/goca/integrations/eso-provider

go 1.24
