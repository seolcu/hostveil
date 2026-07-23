package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// TestTopLevelHelpFlags guards issue #520: `--help`/`-h` must print the
// top-level usage, not the scan subcommand's flag usage.
func TestTopLevelHelpFlags(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		var code int
		out := captureStdout(t, func() { code = run(context.Background(), []string{arg}) })
		if code != 0 {
			t.Errorf("run(%q) exit = %d, want 0", arg, code)
		}
		if strings.Contains(out, "Usage of scan") {
			t.Errorf("run(%q) leaked scan flag usage:\n%s", arg, out)
		}
		if !strings.Contains(out, "guided hardening") {
			t.Errorf("run(%q) did not print top-level usage:\n%s", arg, out)
		}
	}
}

// TestTopLevelVersionFlags guards issue #520: `--version`/`-V` must print the
// version, not error out inside the scan flag set.
func TestTopLevelVersionFlags(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-V"} {
		var code int
		out := captureStdout(t, func() { code = run(context.Background(), []string{arg}) })
		if code != 0 {
			t.Errorf("run(%q) exit = %d, want 0", arg, code)
		}
		if !strings.Contains(out, "hostveil "+version) {
			t.Errorf("run(%q) = %q, want it to contain version %q", arg, out, version)
		}
	}
}
