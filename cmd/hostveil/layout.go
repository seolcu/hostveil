package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/ui/tui"
)

// This file is temporary and goes with the layout picker. It is the TUI's
// half of the same experiment the dashboard runs in localStorage: six
// arrangements shipped behind a selector so one can be chosen against a real
// host. When that is decided, this file goes.
//
// It lives in cmd/hostveil rather than in internal/ui/tui for the reason
// theme.go does: the state directory is internal/history's, and the layering
// test forbids a UI package from importing it.

// layoutPrefFile is a remembered choice, not configuration — nothing in it
// changes what hostveil detects, scores, or does to a host. It sits beside
// the theme preference in the same state directory.
const layoutPrefFile = "layout"

// loadLayoutPref returns the saved arrangement ID, or "" when there is none
// or it cannot be read. Validation is the TUI's: it resolves an unknown ID to
// the shipped arrangement, so a preference written by a build that had a
// layout this one does not is not an error anywhere.
func loadLayoutPref() string {
	b, err := os.ReadFile(filepath.Join(stateDir(), layoutPrefFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// saveLayoutPref records id as the remembered arrangement. An unknown ID is
// refused rather than written, so the loader never has to reason about how a
// bad value got there.
func saveLayoutPref(id string) error {
	if _, ok := tui.LookupLayout(id); !ok {
		return &unknownLayoutError{id: id}
	}
	dir := stateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, layoutPrefFile), []byte(id+"\n"), 0o600)
}

type unknownLayoutError struct{ id string }

func (e *unknownLayoutError) Error() string {
	return "unknown layout " + e.id + "; available: " + strings.Join(tui.LayoutIDs(), ", ")
}
