package glyph

import (
	"os"
	"path/filepath"
	"strings"
)

// prefFile is the name of the one-line preference file inside hostveil's
// state directory, beside the theme's. It is a remembered choice about what
// the operator's font can draw, not configuration: nothing in it changes
// what hostveil detects, scores, or does to a host.
const prefFile = "glyphs"

// Load returns the set saved in dir, or "" when there is none, it cannot be
// read, or it names a set that no longer exists. A stale or corrupt
// preference must never keep an interface from starting.
func Load(dir string) string {
	if dir == "" {
		return ""
	}
	// G304: dir is the state directory cmd/hostveil resolved, and prefFile
	// is a constant. The variable is the directory, not the name, and the
	// worst a wrong one does is fail to find a one-line preference file.
	//nolint:gosec // G304: a fixed file name under the state directory
	b, err := os.ReadFile(filepath.Join(dir, prefFile))
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(string(b))
	if _, ok := Lookup(name); !ok {
		return ""
	}
	return name
}

// Save records name as the remembered set. An unknown name is refused
// rather than written, so Load never has to reason about how a bad value
// got there.
func Save(dir, name string) error {
	if _, ok := Lookup(name); !ok {
		return &unknownSetError{name: name}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, prefFile), []byte(name+"\n"), 0o600)
}

// Resolve picks the set to draw with: an explicit flag wins, then the
// environment, then the saved preference, then Plain.
//
// Only the flag can fail, for the reason theme.Resolve gives: a user who
// typed --glyphs deserves to be told they typed it wrong, while a stale
// environment variable or preference file falls back silently because
// neither was typed just now and neither is worth refusing to start over.
func Resolve(flag, env, dir string) (Set, error) {
	if flag != "" {
		s, ok := Lookup(flag)
		if !ok {
			return Plain, &unknownSetError{name: flag}
		}
		return s, nil
	}
	if s, ok := Lookup(env); ok {
		return s, nil
	}
	if s, ok := Lookup(Load(dir)); ok {
		return s, nil
	}
	return Plain, nil
}
