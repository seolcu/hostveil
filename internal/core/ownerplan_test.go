package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
)

// The plan names an owner change and the summary shows it, without applying
// anything — planning is pure, so it can be tested without the root a chown
// to another account would need.
func TestAnOwnerChangeIsPlannedAndShown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	target := os.Getuid() + 1
	a := fix.Action{Kind: fix.ActionMode, Paths: []string{path},
		Mode: func(m os.FileMode) os.FileMode { return m }, ChownUID: &target}
	changes, err := planModes(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !changes[0].owner || changes[0].uid != os.Getuid() || changes[0].gid != os.Getgid() {
		t.Fatalf("plan = %+v", changes)
	}
	if got := modeTable(changes); !strings.Contains(got, "owner uid") || strings.Contains(got, "0640 →") {
		t.Errorf("summary %q: it must show the owner change and no mode change", got)
	}

	// The owner it already has is not a change.
	own := os.Getuid()
	a.ChownUID = &own
	if changes, _ := planModes(a); len(changes) != 0 {
		t.Errorf("a file already owned by the target is planned anyway: %+v", changes)
	}
}
