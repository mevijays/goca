package cli

import (
	"os"

	"github.com/mevijays/goca/internal/termio"
)

// These are thin unexported shims over internal/termio, which the remote
// client (internal/rcli) shares so both binaries render identically. Keeping
// the shims means the ~530 existing call sites in this package did not have to
// change when the helpers moved.
//
// table is a wrapper struct rather than a type alias on purpose: an alias
// would expose termio.Table's exported Row/Flush and break every existing
// t.row(...) / t.flush() call site.

func printJSON(v any) error    { return termio.PrintJSON(v) }
func section(title string)     { termio.Section(title) }
func kv(key string, value any) { termio.KV(key, value) }

func ok(format string, args ...any)   { termio.OK(format, args...) }
func warn(format string, args ...any) { termio.Warn(format, args...) }
func info(format string, args ...any) { termio.Info(format, args...) }

func writeOut(path string, data []byte, mode os.FileMode) error {
	return termio.WriteOut(path, data, mode)
}

func interactive() bool                     { return termio.Interactive() }
func ask(prompt, def string) string         { return termio.Ask(prompt, def) }
func askRequired(prompt, def string) string { return termio.AskRequired(prompt, def) }
func askInt(prompt string, def int) int     { return termio.AskInt(prompt, def) }
func askYesNo(prompt string, def bool) bool { return termio.AskYesNo(prompt, def) }

func askChoice(prompt string, options []string, def string) string {
	return termio.AskChoice(prompt, options, def)
}

func askPassword(prompt string, confirm bool) (string, error) {
	return termio.AskPassword(prompt, confirm)
}

type table struct{ *termio.Table }

func newTable(headers ...string) *table { return &table{termio.NewTable(headers...)} }
func (t *table) row(cells ...any)       { t.Table.Row(cells...) }
func (t *table) flush()                 { t.Table.Flush() }
