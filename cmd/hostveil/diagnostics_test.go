package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// diagnostics replaced bugreport's --send path with nothing: it collects and
// prints, and never reaches the network on its own. These tests are about
// that boundary staying true, plus the two things it still has to get right
// — writing to --output and telling the operator where to paste the result.

func TestDiagnosticsWritesToOutputWithoutPrinting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; HOME does not redirect history.DefaultDir")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")

	code, out := runCmd(t, func() int {
		return cmdDiagnostics(context.Background(), []string{"--output", path})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "Wrote "+path) {
		t.Errorf("stdout does not confirm the write:\n%s", out)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "# hostveil diagnostics") {
		t.Errorf("report does not start with the expected heading:\n%s", data)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("report mode = %v, want 0600", fi.Mode().Perm())
	}
}

// With no --output, the report goes to stdout and diagnostics names where a
// human pastes it — there is no --send left to do that step automatically.
func TestDiagnosticsWithoutOutputPrintsAndNamesWhereToPasteIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; HOME does not redirect history.DefaultDir")
	}
	t.Setenv("HOME", t.TempDir())

	code, out := runCmd(t, func() int {
		return cmdDiagnostics(context.Background(), nil)
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "# hostveil diagnostics") {
		t.Errorf("report was not printed:\n%s", out)
	}
	if !strings.Contains(out, "github.com/seolcu/hostveil/issues/new") {
		t.Errorf("output does not say where to paste the report:\n%s", out)
	}
}

// --unredacted is the one flag that changes the content rather than the
// destination, and it used to also gate --send; there is nothing left to
// refuse combining it with.
func TestDiagnosticsUnredactedKeepsIPsVerbatim(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; HOME does not redirect history.DefaultDir")
	}
	t.Setenv("HOME", t.TempDir())

	trace := filepath.Join(t.TempDir(), "trace.log")
	if err := os.WriteFile(trace, []byte("connect 203.0.113.5:22"), 0o600); err != nil {
		t.Fatal(err)
	}

	redacted, err := buildDiagnosticsReport(diagnosticsOptions{trace: trace, redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted, "203.0.113.5") {
		t.Errorf("redacted report still carries the raw IP:\n%s", redacted)
	}

	raw, err := buildDiagnosticsReport(diagnosticsOptions{trace: trace, redact: false})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "203.0.113.5") {
		t.Errorf("--unredacted report lost the raw IP:\n%s", raw)
	}
}
