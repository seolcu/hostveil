package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The remembered arrangement, resolved the way the theme and the symbol set
// are: an explicit flag wins, then the environment, then the saved choice,
// then what hostveil ships.
//
// It used to be the odd one out. The flag existed, the picker saved a file,
// and the two were wired together by hand in cmd/hostveil with no environment
// layer at all — so `HOSTVEIL_THEME=nord` and `HOSTVEIL_GLYPHS=nerd` worked in
// a systemd unit or a shell profile and there was no way to say the same thing
// about the arrangement. The asymmetry was invisible from inside each half:
// the flag worked, the picker worked, and nothing pointed at the layer that
// was missing.
//
// It lives here rather than in cmd/hostveil for the same reason theme.Load
// does: this is where the registry is, so this is where a preference can be
// validated against it, and a package test can reach it. The *directory* is
// still the caller's to supply — internal/ui may not import internal/history,
// which is what knows where hostveil keeps state.

// layoutPrefFile is the one-line preference file inside hostveil's state
// directory. It is a remembered choice, not configuration: nothing in it
// changes what hostveil detects, scores, or does to a host.
const layoutPrefFile = "layout"

// LoadLayoutPref returns the arrangement ID saved in dir, or "" when there is
// none, it cannot be read, or it names an arrangement that no longer exists.
// A stale or corrupt preference must never keep a UI from starting.
func LoadLayoutPref(dir string) string {
	if dir == "" {
		return ""
	}
	// G304: dir is the state directory cmd/hostveil resolved, and the file
	// name is a constant. The variable is the directory, not the name.
	//nolint:gosec // G304: a fixed file name under the state directory
	b, err := os.ReadFile(filepath.Join(dir, layoutPrefFile))
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(b))
	if _, ok := LookupLayout(id); !ok {
		return ""
	}
	return id
}

// SaveLayoutPref records id as the remembered arrangement. An unknown ID is
// refused rather than written, so LoadLayoutPref never has to reason about how
// a bad value got there.
func SaveLayoutPref(dir, id string) error {
	if _, ok := LookupLayout(id); !ok {
		return &UnknownLayoutError{ID: id}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, layoutPrefFile), []byte(id+"\n"), 0o600)
}

// ResolveLayout picks the arrangement to start in: an explicit flag wins, then
// the environment, then the saved preference, then the shipped default.
//
// Only the flag can fail — someone who typed --layout deserves to be told they
// typed it wrong. An unrecognised environment variable or saved preference
// falls back silently, because neither was typed just now and neither is worth
// refusing to start over. A preference written by a build that had an
// arrangement this one does not is exactly that case.
func ResolveLayout(flag, env, dir string) (Layout, error) {
	if flag != "" {
		l, ok := LookupLayout(flag)
		if !ok {
			return DefaultLayout(), &UnknownLayoutError{ID: flag}
		}
		return l, nil
	}
	if l, ok := LookupLayout(env); ok {
		return l, nil
	}
	if l, ok := LookupLayout(LoadLayoutPref(dir)); ok {
		return l, nil
	}
	return DefaultLayout(), nil
}

// UnknownLayoutError names what was asked for and what there is. Exported
// because cmd/hostveil prints it, and the dashboard's --layout has to fail
// the same way the terminal's does.
type UnknownLayoutError struct{ ID string }

func (e *UnknownLayoutError) Error() string {
	return fmt.Sprintf("unknown layout %q; available: %s", e.ID, strings.Join(LayoutIDs(), ", "))
}
