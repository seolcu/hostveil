package history

import (
	"os"
	"path/filepath"
	"sort"
)

// maxScans caps how many past scan snapshots are retained.
const maxScans = 30

func (s *Store) scansDir() string { return filepath.Join(s.dir, "scans") }

// SaveReport persists a scan snapshot (opaque JSON) under a sortable id,
// pruning old snapshots beyond maxScans.
func (s *Store) SaveReport(id string, data []byte) error {
	dir := s.scansDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), data, 0o600); err != nil {
		return err
	}
	s.pruneScans()
	return nil
}

// LastReport returns the most recent saved scan snapshot, or ok=false if
// none exists yet.
func (s *Store) LastReport() ([]byte, bool, error) {
	names, err := scanFiles(s.scansDir())
	if err != nil {
		return nil, false, err
	}
	if len(names) == 0 {
		return nil, false, nil
	}
	data, err := os.ReadFile(filepath.Join(s.scansDir(), names[len(names)-1]))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (s *Store) pruneScans() {
	names, err := scanFiles(s.scansDir())
	if err != nil || len(names) <= maxScans {
		return
	}
	for _, name := range names[:len(names)-maxScans] {
		_ = os.Remove(filepath.Join(s.scansDir(), name))
	}
}

// scanFiles returns scan snapshot filenames sorted oldest→newest (the ids
// are timestamp-prefixed, so lexical order is chronological).
func scanFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
