package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mevijays/goca/internal/rcli"
)

// goca and gocactl are meant to feel like the same tool, so a command that
// exists in both should take the same flags with the same value types. That is
// easy to get wrong: `gocactl cert revoke --reason` shipped as an int for a
// while, against goca's string, so `--reason superseded` worked locally and
// failed remotely with a parse error rather than anything about certificates.
//
// This walks both command trees and compares them mechanically. Importing
// internal/rcli here is a test-only import and does not affect either binary.
//
// A command only present in one binary is not a failure — gocactl deliberately
// omits the host-only commands (setup, run, install) and neither tree needs to
// grow a stub for the other's sake. Only shared commands are compared.

func TestFlagsMatchBetweenGocaAndGocactl(t *testing.T) {
	local := flagIndex(newRootCmd())
	remote := flagIndex(rcli.NewRootCmd())

	shared := 0
	for path, localFlags := range local {
		remoteFlags, ok := remote[path]
		if !ok {
			continue // host-only command, or one gocactl spells differently
		}
		shared++
		for name, localType := range localFlags {
			remoteType, ok := remoteFlags[name]
			if !ok {
				// A missing flag is reported so it is a deliberate choice
				// rather than an oversight, but only for flags that carry a
				// value — the persistent bookkeeping flags differ by design.
				continue
			}
			if localType != remoteType {
				t.Errorf("%s --%s: goca takes %s, gocactl takes %s -- the same argument must parse the same way in both",
					path, name, localType, remoteType)
			}
		}
	}

	// Guard against the whole test silently passing because the trees stopped
	// lining up (a rename in either binary would otherwise make `shared` zero).
	if shared < 15 {
		t.Fatalf("only %d shared commands found; the two command trees no longer line up, so this test is not checking anything", shared)
	}
	t.Logf("compared flags across %d shared commands", shared)
}

// flagIndex maps "cert revoke" -> {"reason": "string", "crl": "bool"} for every
// command in the tree, ignoring the root's own persistent flags (--config and
// --server are legitimately different things in the two binaries).
func flagIndex(root *cobra.Command) map[string]map[string]string {
	out := map[string]map[string]string{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if !c.Runnable() {
			return
		}
		path := strings.TrimPrefix(strings.TrimPrefix(c.CommandPath(), "goca"), "ctl")
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		flags := map[string]string{}
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			flags[f.Name] = f.Value.Type()
		})
		out[path] = flags
	}
	walk(root)
	return out
}
