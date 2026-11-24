// Package resultcache stores scan results that are expensive to compute, in
// Hostveil's own state directory, keyed by a digest the caller derives from
// everything the result depends on.
//
// It lives outside internal/check because checkers are read-only: a checker
// is handed a Dir and calls Get and Put, and the writes happen here, in
// Hostveil's directory, never on the host being scanned
// (internal/docs/readonly_test.go).
package resultcache

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/platform"
)

// Dir is a directory of entries, one file per key.
type Dir struct {
	path     string
	keep     int
	maxBytes int64
}

// New returns a cache rooted at path that keeps the keep most recently used
// entries and refuses to read back an entry larger than maxBytes.
func New(path string, keep int, maxBytes int64) *Dir {
	return &Dir{path: path, keep: keep, maxBytes: maxBytes}
}

// validKey accepts the hex digests callers use as keys, which keeps a key
// from naming a path outside the directory.
func validKey(key string) bool {
	if len(key) < 16 || len(key) > 128 {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

func (d *Dir) file(key string) string { return filepath.Join(d.path, key+".json") }

// Get returns the entry stored under key. A hit refreshes the entry's
// modification time, which is what Prune orders by.
func (d *Dir) Get(key string) ([]byte, bool) {
	if d == nil || !validKey(key) {
		return nil, false
	}
	p := d.file(key)
	data, err := platform.ReadFileBounded(p, d.maxBytes)
	if err != nil {
		return nil, false
	}
	now := time.Now()
	_ = os.Chtimes(p, now, now)
	return data, true
}

// Put stores data under key. Errors are dropped: an entry that cannot be
// written costs the next scan time and nothing else.
func (d *Dir) Put(key string, data []byte) {
	if d == nil || !validKey(key) {
		return
	}
	if err := os.MkdirAll(d.path, 0o700); err != nil {
		return
	}
	_ = platform.WriteFileAtomic(d.file(key), data, 0o600)
}

// Prune keeps the most recently used entries and removes the rest.
func (d *Dir) Prune() {
	if d == nil {
		return
	}
	entries, err := os.ReadDir(d.path)
	if err != nil {
		return
	}
	type entry struct {
		name string
		mod  time.Time
	}
	var all []entry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, entry{e.Name(), info.ModTime()})
	}
	if len(all) <= d.keep {
		return
	}
	slices.SortFunc(all, func(a, b entry) int { return b.mod.Compare(a.mod) })
	for _, e := range all[d.keep:] {
		_ = os.Remove(filepath.Join(d.path, e.name))
	}
}
