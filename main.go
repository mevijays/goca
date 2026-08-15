// Command goca is a single-binary certificate authority: a CLI, a REST API and
// an embedded web portal, all backed by one SQLite database.
package main

import (
	"os"

	"github.com/mevijays/goca/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
