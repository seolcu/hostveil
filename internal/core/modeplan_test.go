package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/textwidth"
)

// applyMode used to plan the changes and then call previewMode, which
// planned them again: two Lstat passes over the same paths inside one
// apply. The paths it chmod'ed and recorded for rollback came from the
// first pass, while the summary it stored in the checkpoint came from the
// second, so a mode altered in between left the checkpoint describing a set
// that was never applied.
//
// modeTable renders a plan already made, so the two cannot differ. These
// tests hold the table to that plan.

func modeAction(t *testing.T, paths []string, to os.FileMode) fix.Action {
	t.Helper()
	return fix.Action{
		Label: "tighten", Kind: fix.ActionMode, Paths: paths,
		Mode: func(cur os.FileMode) os.FileMode { return cur.Type() | to },
	}
}

func TestModeTableDescribesExactlyThePlan(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"a.conf", "b.conf", "c.conf"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o666); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}

	changes, err := planModes(modeAction(t, paths, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 {
		t.Fatalf("planned %d changes, want 3", len(changes))
	}

	table := modeTable(changes)
	for _, c := range changes {
		if !strings.Contains(table, c.path) {
			t.Errorf("the table omits %s, which the plan will change", c.path)
		}
	}
	// One row per planned change and no more: a row for a path that is not
	// in the plan is the checkpoint recording work nobody did.
	if got := len(strings.Split(strings.TrimRight(table, "\n"), "\n")); got != len(changes) {
		t.Errorf("table has %d rows for %d planned changes:\n%s", got, len(changes), table)
	}
}

// The empty plan has to keep saying so, since applyMode distinguishes it
// from a real one before it reaches the table.
func TestModeTableOnAnEmptyPlan(t *testing.T) {
	if got := modeTable(nil); !strings.Contains(got, "already as strict") {
		t.Errorf("modeTable(nil) = %q", got)
	}
}

// The arrow column is aligned in display columns. Measuring the path with
// len() counts bytes, so a single non-ASCII path threw every arrow in the
// table out of line — and paths come from the operator.
func TestModeTableAlignsNonASCIIPaths(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"짧은.conf", "a-much-longer-ascii-name.conf", "설정파일.conf"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o666); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	changes, err := planModes(modeAction(t, paths, 0o600))
	if err != nil {
		t.Fatal(err)
	}

	var col = -1
	for _, line := range strings.Split(strings.TrimRight(modeTable(changes), "\n"), "\n") {
		at := strings.Index(line, "→")
		if at < 0 {
			t.Fatalf("row has no mode column: %q", line)
		}
		got := textwidth.Of(line[:at])
		if col == -1 {
			col = got
			continue
		}
		if got != col {
			t.Errorf("modes start at column %d on one row and %d on another — the table is ragged:\n%s",
				col, got, modeTable(changes))
			break
		}
	}
}
