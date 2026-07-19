package platform

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

// A failing command's stderr is what actually explains the failure ("permission
// denied while trying to connect to the Docker daemon socket"). os/exec strands
// it on the ExitError, leaving callers to report a bare "exit status 1", which
// is what every UI would then show as the reason a domain failed.
func TestRunSurfacesStderr(t *testing.T) {
	_, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "echo 'permission denied' >&2; exit 1")
	if err == nil {
		t.Fatal("expected an error from a non-zero exit")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("stderr not surfaced in error: %q", err)
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("original exit error not preserved: %q", err)
	}
}

// Reasons built from these errors are rendered in every UI and persisted to
// disk with the scan report, so a command that dumps a megabyte of stderr must
// not drag all of it along.
func TestRunTruncatesStderr(t *testing.T) {
	_, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "head -c 5000 /dev/zero | tr '\\0' 'x' >&2; exit 1")
	if err == nil {
		t.Fatal("expected an error from a non-zero exit")
	}
	if n := utf8.RuneCountInString(err.Error()); n > maxStderr+80 {
		t.Errorf("error message not truncated: %d runes", n)
	}
}

// Truncation is by rune, so a non-ASCII message never ends in a broken
// sequence — these strings reach users' terminals.
func TestCleanStderrTruncatesOnRuneBoundary(t *testing.T) {
	got := cleanStderr([]byte(strings.Repeat("가", maxStderr*2)))
	if !utf8.ValidString(got) {
		t.Errorf("truncation split a rune: %q", got)
	}
}

// Multi-line stderr collapses to one line: DomainResult.Reason is rendered
// inline in list views that assume a single line.
func TestCleanStderrCollapsesToOneLine(t *testing.T) {
	got := cleanStderr([]byte("first line\nsecond line\n\n  third  \n"))
	if want := "first line second line third"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A command that succeeds, and one that fails silently, must be unchanged.
func TestRunLeavesOtherErrorsAlone(t *testing.T) {
	out, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "echo hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("got %q, want %q", out, "hello")
	}

	if _, err := (DefaultRunner{}).Run(context.Background(), "sh", "-c", "exit 3"); err == nil {
		t.Fatal("expected an error from a non-zero exit")
	} else if err.Error() != "exit status 3" {
		t.Errorf("empty stderr should leave the error untouched, got %q", err)
	}
}
