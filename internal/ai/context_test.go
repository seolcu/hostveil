package ai

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContextSaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state") // does not exist yet
	if err := SaveContext(dir, "a personal media server"); err != nil {
		t.Fatalf("SaveContext: %v", err)
	}
	if got := LoadContext(dir); got != "a personal media server" {
		t.Errorf("LoadContext = %q, want the saved text", got)
	}

	fi, err := os.Stat(filepath.Join(dir, contextFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("context file mode = %v, want 0600", perm)
	}
}

func TestContextSaveEmptyClearsIt(t *testing.T) {
	dir := t.TempDir()
	if err := SaveContext(dir, "something"); err != nil {
		t.Fatal(err)
	}
	if err := SaveContext(dir, ""); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	if got := LoadContext(dir); got != "" {
		t.Errorf("LoadContext = %q after clearing, want empty", got)
	}
	if _, err := os.Stat(filepath.Join(dir, contextFile)); !os.IsNotExist(err) {
		t.Error("the context file should have been removed")
	}
	// Clearing an already-clear context is not an error.
	if err := SaveContext(dir, ""); err != nil {
		t.Errorf("clearing an unset context: %v", err)
	}
}

func TestContextSaveRefusesOverLength(t *testing.T) {
	dir := t.TempDir()
	if err := SaveContext(dir, strings.Repeat("x", maxContextBytes+1)); err == nil {
		t.Fatal("SaveContext accepted text over the byte limit")
	}
	if got := LoadContext(dir); got != "" {
		t.Errorf("LoadContext = %q, an oversized save should have written nothing", got)
	}
}

// A missing directory or file must read as "no context set" rather than an
// error a caller has to handle before it can build a prompt.
func TestContextLoadTolerant(t *testing.T) {
	if got := LoadContext(""); got != "" {
		t.Errorf("LoadContext(\"\") = %q, want empty", got)
	}
	if got := LoadContext(filepath.Join(t.TempDir(), "does-not-exist")); got != "" {
		t.Errorf("LoadContext of a missing dir = %q, want empty", got)
	}
}
