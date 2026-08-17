package rcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The config file holds live API tokens. Any command that prints the config
// must redact them unless the user explicitly asked for them with
// --show-token, and that has to hold for --json as much as for the table:
// `config get-contexts --json` used to dump tokens in full, which is exactly
// the sort of thing that ends up pasted into an issue.
func TestPrintingTheConfigRedactsTokens(t *testing.T) {
	const secret = "goca_abc12345_SUPERSECRETTOKENBODYzzzzzzzzzzzz"

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`current_context: prod
contexts:
    prod:
        server: https://ca.example.com
        token: `+secret+`
        token_id: 3
        user: alice
        role: admin
`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"get-contexts", []string{"config", "get-contexts"}},
		{"get-contexts --json", []string{"config", "get-contexts", "--json"}},
		{"view", []string{"config", "view"}},
		{"view --json", []string{"config", "view", "--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := runCommand(t, path, tc.args...)
			if strings.Contains(out, secret) {
				t.Errorf("`gocactl %s` printed the token in full:\n%s", strings.Join(tc.args, " "), out)
			}
			// The public prefix is fine, and is what makes the output useful for
			// matching a context against `goca token list`.
			if !strings.Contains(out, "goca_abc12345") && !strings.Contains(out, "prod") {
				t.Errorf("`gocactl %s` printed neither the token prefix nor the context name; output is not useful:\n%s",
					strings.Join(tc.args, " "), out)
			}
		})
	}

	// ...and the escape hatch still works, or there would be no way to recover
	// a token for a script.
	if out := runCommand(t, path, "config", "view", "--show-token"); !strings.Contains(out, secret) {
		t.Errorf("`config view --show-token` did not print the token; output:\n%s", out)
	}
}

// runCommand executes one gocactl invocation against a specific config file and
// returns everything it wrote to stdout.
func runCommand(t *testing.T, configPath string, args ...string) string {
	t.Helper()

	realStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	// The command tree reads these package-level flag variables; reset them so
	// one subtest cannot leak --json into the next.
	flagConfig, flagJSON = configPath, false
	defer func() { flagConfig, flagJSON = "", false }()

	root := newRootCmd()
	root.SetArgs(append([]string{"--config", configPath}, args...))
	root.SetOut(w)
	root.SetErr(w)
	runErr := root.Execute()

	w.Close()
	os.Stdout = realStdout
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatalf("gocactl %s failed: %v (output: %s)", strings.Join(args, " "), runErr, buf.String())
	}
	return buf.String()
}
