package theme

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// prefFile is the name of the one-line preference file inside hostveil's
// state directory. It is a remembered choice, not configuration: nothing in
// it changes what hostveil detects, scores, or does to a host.
const prefFile = "theme"

// Load returns the theme ID saved in dir, or "" when there is none, it cannot
// be read, or it names a theme that no longer exists. A stale or corrupt
// preference must never keep a UI from starting.
func Load(dir string) string {
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, prefFile))
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(b))
	if _, ok := Lookup(id); !ok {
		return ""
	}
	return id
}

// Save records id as the remembered theme. An unknown ID is refused rather
// than written, so Load never has to reason about how a bad value got there.
func Save(dir, id string) error {
	if _, ok := Lookup(id); !ok {
		return &unknownThemeError{id: id}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, prefFile), []byte(id+"\n"), 0o600)
}

// Resolve picks the theme to start in: an explicit flag wins, then the
// environment, then the saved preference, then the default.
//
// Only the flag can fail — a user who typed --theme deserves to be told they
// typed it wrong. An unrecognised environment variable or saved preference
// falls back silently, because neither was typed just now and neither is
// worth refusing to start over.
func Resolve(flag, env, dir string) (Theme, error) {
	if flag != "" {
		t, ok := Lookup(flag)
		if !ok {
			return Default(), &unknownThemeError{id: flag}
		}
		return t, nil
	}
	if t, ok := Lookup(env); ok {
		return t, nil
	}
	if t, ok := Lookup(Load(dir)); ok {
		return t, nil
	}
	return Default(), nil
}

type unknownThemeError struct{ id string }

func (e *unknownThemeError) Error() string {
	return fmt.Sprintf("unknown theme %q; available: %s", e.id, strings.Join(IDs(), ", "))
}
