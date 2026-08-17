// Command gocactl is the remote command line for a goca server.
//
// It is the counterpart to the goca binary: the same capabilities, reached
// over the REST API rather than by opening the database. goca must run on the
// server host and holds the master key; gocactl runs anywhere, holds only an
// API token, and can do exactly what the signed-in account's role allows.
package main

import (
	"os"

	"github.com/mevijays/goca/internal/rcli"
)

func main() {
	os.Exit(rcli.Execute())
}
