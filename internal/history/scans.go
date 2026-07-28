package history

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/platform"
)

// maxScans caps how many past scan snapshots are retained.
const maxScans = 30

func (s *Store) scansDir() string { return filepath.Join(s.dir, "scans") }

// SaveReport persists a scan snapshot (opaque JSON) under a sortable id,
// pruning old snapshots beyond maxScans.
//
// The write is atomic for the same reason every other write in this package
// is, even though a scan snapshot is not a backup. The newest snapshot is
// the baseline: LastReport reads it and nothing else, and the next scan
// diffs against it to decide what is newly appeared, resolved, or changed.
// A snapshot torn by a crash — or by delayed allocation on XFS or btrfs —
// therefore does not degrade the delta, it destroys it: the file fails to
// unmarshal, and the run that follows either reports no delta at all or
// announces the whole host as new. os.WriteFile truncates before it writes,
// so the window where that file is a half-written prefix of valid JSON is
// real, and it lands on exactly the file the next scan depends on.
func (s *Store) SaveReport(id string, data []byte) error {
	dir := s.scansDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := platform.WriteFileAtomic(filepath.Join(dir, id+".json"), data, 0o600); err != nil {
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

// ScanSnapshot is one saved scan: when it ran, and the opaque bytes it was
// saved as. The store deliberately does not parse them — it holds
// snapshots, it does not know what a report is — so the caller unmarshals.
type ScanSnapshot struct {
	ID   string
	At   time.Time
	Data []byte
}

// scanIDTime is the timestamp layout NewScanID writes. The ids are
// timestamp-prefixed so a lexical sort is chronological, which pruning and
// LastReport both already rely on; this reads the same prefix back.
const scanIDTime = "20060102-150405.000"

// ListReports returns every retained scan snapshot, oldest first.
//
// Thirty of these have been kept and pruned since the store was written,
// and nothing ever read more than the newest one — LastReport takes the
// last element and every interface shows only "since last scan". The data
// for a trend was on disk the whole time with no way to ask for it.
//
// A snapshot whose id does not carry a parseable timestamp, or that cannot
// be read, is skipped rather than failing the call. This is a history
// view: one unreadable entry should cost that entry, not the whole series
// — the same reasoning as Store.List returning what it could read
// alongside its error.
func (s *Store) ListReports() ([]ScanSnapshot, error) {
	names, err := scanFiles(s.scansDir())
	if err != nil {
		return nil, err
	}
	out := make([]ScanSnapshot, 0, len(names))
	for _, name := range names {
		id := strings.TrimSuffix(name, ".json")
		at, err := scanIDAt(id)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.scansDir(), name))
		if err != nil {
			continue
		}
		out = append(out, ScanSnapshot{ID: id, At: at, Data: data})
	}
	return out, nil
}

// scanIDAt recovers the scan time from its id.
func scanIDAt(id string) (time.Time, error) {
	if len(id) < len(scanIDTime) {
		return time.Time{}, fmt.Errorf("scan id %q is too short to carry a timestamp", id)
	}
	return time.Parse(scanIDTime, id[:len(scanIDTime)])
}
