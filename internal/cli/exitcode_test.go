package cli

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestExitCodeConstants(t *testing.T) {
	if ExitOK != 0 {
		t.Errorf("ExitOK = %d, want 0", ExitOK)
	}
	if ExitHit != 1 {
		t.Errorf("ExitHit = %d, want 1", ExitHit)
	}
	if ExitError != 2 {
		t.Errorf("ExitError = %d, want 2", ExitError)
	}
}

func TestNewRoot_Subcommands(t *testing.T) {
	root := NewRoot()
	want := []string{"scan", "fix", "rollback", "explain", "suppress", "version", "tui", "web", "ai"}
	got := map[string]bool{}
	for _, c := range root.Commands() {
		got[c.Name()] = true
	}
	for _, n := range want {
		if !got[n] {
			t.Errorf("NewRoot() is missing subcommand %q; got %v", n, keys(got))
		}
	}
}

func TestNewRoot_PersistentFlags(t *testing.T) {
	root := NewRoot()
	want := []string{"config", "log-level", "log-file", "no-color", "color"}
	got := map[string]bool{}
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		got[f.Name] = true
	})
	for _, n := range want {
		if !got[n] {
			t.Errorf("NewRoot() is missing persistent flag --%s; got %v", n, keys(got))
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
