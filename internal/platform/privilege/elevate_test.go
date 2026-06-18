//go:build linux

package privilege

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDetect_NoHelper(t *testing.T) {
	// On a normal CI / dev box at least one helper exists. We only
	// assert the function is callable and returns a known value.
	got := Detect()
	switch got {
	case HelperSudo, HelperPkexec, HelperNone:
	default:
		t.Fatalf("Detect() returned unknown helper: %q", got)
	}
}

func TestRun_NoneHelper(t *testing.T) {
	_, err := Run(context.Background(), HelperNone, []Command{{Name: "true"}})
	if err != ErrElevationRequired {
		t.Fatalf("Run(None) error = %v, want ErrElevationRequired", err)
	}
}

func TestRun_EmptyCommands(t *testing.T) {
	res, err := Run(context.Background(), HelperSudo, nil)
	if err != nil {
		t.Fatalf("Run(empty) error = %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("Run(empty) returned %d results, want 0", len(res))
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"echo":    "'echo'",
		"a b":     "'a b'",
		"it's":    "'it'\\''s'",
		"rm -rf":  "'rm -rf'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetect_FakeHelper(t *testing.T) {
	// Build a temp dir with a fake `sudo` symlink and prepend it to
	// $PATH. Detect should pick it up.
	tmp := t.TempDir()
	for _, name := range []string{"sudo", "pkexec"} {
		_ = os.Symlink("/bin/true", filepath.Join(tmp, name))
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	if got := Detect(); got == HelperNone {
		t.Fatalf("Detect() with fake helper returned None, want sudo or pkexec")
	}
}
