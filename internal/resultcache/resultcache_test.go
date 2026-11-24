package resultcache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func key(i int) string {
	return strings.Repeat("0", 60) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16]) + "ab"
}

// Prune keeps the most recently used entries and drops the rest.
func TestPruneKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	d := New(dir, 4, 1<<20)
	base := time.Now().Add(-time.Hour)
	for i := range 7 {
		d.Put(key(i), []byte("{}"))
		mod := base.Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(d.file(key(i)), mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	d.Prune()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 4 {
		t.Fatalf("want 4 entries, got %d", len(entries))
	}
	for i := range 3 {
		if _, ok := d.Get(key(i)); ok {
			t.Fatalf("entry %d is among the oldest and should be gone", i)
		}
	}
}

// A hit counts as a use, so an old entry that is still read survives.
func TestGetRefreshesAnEntry(t *testing.T) {
	dir := t.TempDir()
	d := New(dir, 1, 1<<20)
	d.Put(key(0), []byte("{}"))
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(d.file(key(0)), old, old); err != nil {
		t.Fatal(err)
	}
	d.Put(key(1), []byte("{}"))
	if _, ok := d.Get(key(0)); !ok {
		t.Fatal("entry 0 was stored")
	}
	d.Prune()
	if _, ok := d.Get(key(0)); !ok {
		t.Fatal("the entry read last must survive the prune")
	}
}

// A key is a hex digest, so nothing a caller passes can name a path outside
// the directory.
func TestKeysCannotEscapeTheDirectory(t *testing.T) {
	dir := t.TempDir()
	d := New(filepath.Join(dir, "cache"), 4, 1<<20)
	for _, k := range []string{"../escape", "", "zz", strings.Repeat("a", 200)} {
		d.Put(k, []byte("{}"))
		if _, ok := d.Get(k); ok {
			t.Errorf("key %q must be refused", k)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) > 0 {
		if sub, _ := os.ReadDir(filepath.Join(dir, "cache")); len(sub) > 0 || len(entries) > 1 {
			t.Fatalf("a refused key wrote something: %v", entries)
		}
	}
}

// An entry larger than the bound is a miss.
func TestOversizedEntryIsAMiss(t *testing.T) {
	d := New(t.TempDir(), 4, 8)
	d.Put(key(0), []byte(`{"a":"0123456789"}`))
	if _, ok := d.Get(key(0)); ok {
		t.Fatal("an entry over maxBytes must not be read back")
	}
}
