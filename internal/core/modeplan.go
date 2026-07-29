package core

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/textwidth"
)

// modeChange is one file whose permission bits a mode action would alter.
type modeChange struct {
	path     string
	from, to fs.FileMode
}

// planModes stats every path and computes its new mode, purely. It reports
// only the paths that would actually change, so a fix cannot claim credit
// for files that were already compliant.
//
// A stat failure aborts the whole plan rather than skipping the file: a fix
// that silently tightened three of four files would report success while
// leaving the fourth exposed.
//
// Lstat plus a type check, never Stat. Mode fixes reach into user homes
// (agent.config-perms), where the path is the account's to shape: a symlink
// left where the config file was would send root's chmod to whatever the
// link points at. Refusing loudly rather than skipping keeps the no-silent-
// partial-success rule above.
func planModes(a fix.Action) ([]modeChange, error) {
	var changes []modeChange
	for _, p := range a.Paths {
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if m := fi.Mode(); !m.IsRegular() && !m.IsDir() {
			return nil, fmt.Errorf("%s is not a regular file or directory (%v); refusing to change its mode", p, m.Type())
		}
		cur := fi.Mode()
		next := a.Mode(cur)
		if next != cur {
			changes = append(changes, modeChange{path: p, from: cur, to: next})
		}
	}
	return changes, nil
}

// modeTable renders a plan that has already been made.
//
// It is separate from previewMode so that applyMode can describe the very
// changes it is about to make. applyMode used to call planModes and then
// previewMode, which planned again — two Lstat passes over the same paths
// inside one apply, and two chances for the answer to differ. The paths it
// chmod'ed and recorded for rollback came from the first pass while the
// summary stored in the checkpoint came from the second, so a mode altered
// between them left the checkpoint describing a set that was never applied.
// Rollback still worked, since the restore data came from the first pass;
// the record of what happened was the part that lied.
//
// The column is measured in display columns. len() counts bytes, which
// misaligns the arrows for any path that is not ASCII — and paths come from
// the operator.
func modeTable(changes []modeChange) string {
	if len(changes) == 0 {
		return "Permissions are already as strict as required."
	}
	width := 0
	for _, c := range changes {
		if w := textwidth.Of(c.path); w > width {
			width = w
		}
	}
	var b strings.Builder
	for _, c := range changes {
		fmt.Fprintf(&b, "%s  %#o → %#o\n",
			c.path+strings.Repeat(" ", width-textwidth.Of(c.path)), c.from.Perm(), c.to.Perm())
	}
	return b.String()
}
