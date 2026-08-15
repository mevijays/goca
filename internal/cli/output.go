package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

// printJSON writes an indented JSON document to stdout.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// table renders aligned columns on stdout.
type table struct {
	w    *tabwriter.Writer
	cols int
}

func newTable(headers ...string) *table {
	t := &table{w: tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0), cols: len(headers)}
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

func (t *table) row(cells ...any) {
	strs := make([]string, len(cells))
	for i, c := range cells {
		strs[i] = fmt.Sprint(c)
	}
	fmt.Fprintln(t.w, strings.Join(strs, "\t"))
}

func (t *table) flush() { _ = t.w.Flush() }

//
// ---------- interactive prompts ----------
//

var stdin = bufio.NewReader(os.Stdin)

// interactive reports whether stdin is a terminal.
func interactive() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// ask prompts for a line of text, returning def when the user just hits enter.
func ask(prompt, def string) string {
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

// askRequired keeps prompting until a non-empty answer is given.
func askRequired(prompt, def string) string {
	for {
		v := ask(prompt, def)
		if strings.TrimSpace(v) != "" {
			return v
		}
		fmt.Println("  this value is required")
	}
}

// askInt prompts for an integer.
func askInt(prompt string, def int) int {
	for {
		v := ask(prompt, strconv.Itoa(def))
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return n
		}
		fmt.Println("  please enter a number")
	}
}

// askYesNo prompts for a boolean.
func askYesNo(prompt string, def bool) bool {
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

// askChoice prompts for one of a fixed set of options.
func askChoice(prompt string, options []string, def string) string {
	fmt.Printf("%s\n", prompt)
	for i, o := range options {
		marker := " "
		if o == def {
			marker = "*"
		}
		fmt.Printf("  %s %d) %s\n", marker, i+1, o)
	}
	for {
		v := ask("  choice", def)
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

// askPassword reads a password without echoing it.
func askPassword(prompt string, confirm bool) (string, error) {
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

//
// ---------- pretty output ----------
//

func section(title string) {
	fmt.Printf("\n\033[1m%s\033[0m\n", title)
	fmt.Println(strings.Repeat("─", len(title)))
}

func kv(key string, value any) {
	fmt.Printf("  %-22s %v\n", key+":", value)
}

func ok(format string, args ...any) {
	fmt.Printf("✓ "+format+"\n", args...)
}

func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "! "+format+"\n", args...)
}

func info(format string, args ...any) {
	fmt.Printf("  "+format+"\n", args...)
}

// writeOut writes data to a file, or to stdout when path is "-" or empty.
func writeOut(path string, data []byte, mode os.FileMode) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	ok("wrote %s (%d bytes)", path, len(data))
	return nil
}
