// Package termio is the shared terminal presentation layer: aligned tables,
// key/value detail blocks, status lines, interactive prompts and file-or-stdout
// writing.
//
// It exists so the two binaries render identically. `goca` (internal/cli) talks
// to the database directly; `gocactl` (internal/rcli) talks to the REST API. A
// user should not be able to tell which one produced a given table, so both
// draw it with this code rather than each keeping their own copy that would
// drift apart the first time a column width changed.
//
// Everything here is stdlib plus golang.org/x/term - deliberately no
// dependency on internal/store, internal/ca or any database driver, since
// linking those into the thin client would pull in both SQL drivers.
package termio

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

// PrintJSON writes an indented JSON document to stdout.
func PrintJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// PrintRaw writes an already-encoded JSON document to stdout, re-indenting it
// so it matches PrintJSON's shape. It exists for the remote client: passing
// the server's own response body through untouched means `--json` output is a
// faithful view of the API and can never silently drop a field the client's
// structs forgot to declare.
func PrintRaw(raw []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		// Not valid JSON - emit it verbatim rather than failing the command,
		// so an unexpected body is still visible to whoever has to debug it.
		_, err := os.Stdout.Write(raw)
		return err
	}
	out := strings.TrimRight(buf.String(), "\n")
	_, err := fmt.Fprintln(os.Stdout, out)
	return err
}

// Table renders aligned columns on stdout.
type Table struct {
	w    *tabwriter.Writer
	cols int
}

// NewTable starts a table with the given headers, which are upper-cased.
func NewTable(headers ...string) *Table {
	return NewTableTo(os.Stdout, headers...)
}

// NewTableTo is NewTable writing somewhere other than stdout, for tests.
func NewTableTo(w io.Writer, headers ...string) *Table {
	t := &Table{w: tabwriter.NewWriter(w, 0, 4, 2, ' ', 0), cols: len(headers)}
	fmt.Fprintln(t.w, strings.Join(upper(headers), "\t"))
	return t
}

func upper(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(s)
	}
	return out
}

// Row appends one row; cells are rendered with fmt.Sprint.
func (t *Table) Row(cells ...any) {
	strs := make([]string, len(cells))
	for i, c := range cells {
		strs[i] = fmt.Sprint(c)
	}
	fmt.Fprintln(t.w, strings.Join(strs, "\t"))
}

// Flush writes the aligned table out.
func (t *Table) Flush() { _ = t.w.Flush() }

//
// ---------- interactive prompts ----------
//

var stdin = bufio.NewReader(os.Stdin)

// Interactive reports whether stdin is a terminal.
func Interactive() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// Ask prompts for a line of text, returning def when the user just hits enter.
func Ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, err := stdin.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return def
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// AskRequired keeps prompting until a non-empty answer is given.
func AskRequired(prompt, def string) string {
	for {
		v := Ask(prompt, def)
		if strings.TrimSpace(v) != "" {
			return v
		}
		fmt.Println("  this value is required")
	}
}

// AskInt prompts for an integer.
func AskInt(prompt string, def int) int {
	for {
		v := Ask(prompt, strconv.Itoa(def))
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return n
		}
		fmt.Println("  please enter a number")
	}
}

// AskYesNo prompts for a boolean.
func AskYesNo(prompt string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	for {
		fmt.Printf("%s [%s]: ", prompt, d)
		line, _ := stdin.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		fmt.Println("  please answer yes or no")
	}
}

// AskChoice prompts for one of a fixed set of options, by index or by name.
func AskChoice(prompt string, options []string, def string) string {
	fmt.Printf("%s\n", prompt)
	for i, o := range options {
		marker := " "
		if o == def {
			marker = "*"
		}
		fmt.Printf("  %s %d) %s\n", marker, i+1, o)
	}
	for {
		v := Ask("  choice", def)
		v = strings.TrimSpace(v)
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(options) {
			return options[n-1]
		}
		for _, o := range options {
			if strings.EqualFold(o, v) {
				return o
			}
		}
		fmt.Println("  pick one of the listed options")
	}
}

// AskPassword reads a password without echoing it.
func AskPassword(prompt string, confirm bool) (string, error) {
	for {
		fmt.Printf("%s: ", prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		pw := string(b)
		if pw == "" {
			fmt.Println("  password cannot be empty")
			continue
		}
		if !confirm {
			return pw, nil
		}
		fmt.Printf("%s (again): ", prompt)
		b2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		if pw != string(b2) {
			fmt.Println("  passwords did not match, try again")
			continue
		}
		return pw, nil
	}
}

// ReadPasswordStdin reads a password from piped stdin, for non-interactive
// use (`--password-stdin`). A single trailing newline is stripped so
// `printf '%s\n' hunter2 | ...` and `printf '%s' hunter2 | ...` agree.
func ReadPasswordStdin() (string, error) {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

//
// ---------- pretty output ----------
//

// Section prints a bold title with an underline.
func Section(title string) {
	fmt.Printf("\n\033[1m%s\033[0m\n", title)
	fmt.Println(strings.Repeat("─", len(title)))
}

// KV prints one aligned key/value detail line.
func KV(key string, value any) {
	fmt.Printf("  %-22s %v\n", key+":", value)
}

// OK prints a success line to stdout.
func OK(format string, args ...any) {
	fmt.Printf("✓ "+format+"\n", args...)
}

// Warn prints a warning to stderr.
func Warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "! "+format+"\n", args...)
}

// Info prints an indented note to stdout.
func Info(format string, args ...any) {
	fmt.Printf("  "+format+"\n", args...)
}

// WriteOut writes data to a file, or to stdout when path is "-" or empty.
func WriteOut(path string, data []byte, mode os.FileMode) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	OK("wrote %s (%d bytes)", path, len(data))
	return nil
}
