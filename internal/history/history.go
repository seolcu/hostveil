// Package history is hostveil's recovery layer: before any fix changes a
// file, the engine backs the original up here as a checkpoint, so any
// applied change — made from any UI — can be rolled back with one command.
// The checkpoint is the ONLY backup mechanism, which is what makes
// cross-UI rollback correct.
package history

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// BackedFile records one file captured in a checkpoint.
type BackedFile struct {
	Path string      `json:"path"` // original absolute path
	Blob string      `json:"blob"` // filename of the backup blob within the checkpoint
	Mode os.FileMode `json:"mode"`
}

// Checkpoint is a restore point created when a fix is applied.
type Checkpoint struct {
	ID             string       `json:"id"`
	FindingID      string       `json:"finding_id"`
	Label          string       `json:"label"`
	CreatedAt      time.Time    `json:"created_at"`
	Files          []BackedFile `json:"files"`
	Diff           string       `json:"diff,omitempty"`
	RestartService string       `json:"restart_service,omitempty"`
	// Commands records exec-fix commands for the record; exec fixes cannot
	// be auto-rolled-back (Files is empty for them).
	Commands [][]string `json:"commands,omitempty"`
}

// Reversible reports whether the checkpoint can be rolled back (i.e. it
// backed up files).
func (c Checkpoint) Reversible() bool { return len(c.Files) > 0 }

// Store persists checkpoints under a directory.
type Store struct {
	dir string
}

// NewStore returns a Store rooted at dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

// DefaultDir returns the per-user (or system, when root) hostveil data
// directory for checkpoints and reports.
func DefaultDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/hostveil"
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "hostveil")
	}
	return filepath.Join(os.TempDir(), "hostveil")
}

func (s *Store) checkpointsDir() string { return filepath.Join(s.dir, "checkpoints") }

// Save writes a checkpoint: the backup blobs plus a meta.json. backups
// maps each original file path to its original bytes. The stored
// Checkpoint (with resolved blob names) is returned.
func (s *Store) Save(cp Checkpoint, backups map[string][]byte) (Checkpoint, error) {
	dir := filepath.Join(s.checkpointsDir(), cp.ID)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o700); err != nil {
		return Checkpoint{}, err
	}

	cp.Files = cp.Files[:0]
	for path, data := range backups {
		blob := blobName(path)
		mode := os.FileMode(0o600)
		if fi, err := os.Stat(path); err == nil {
			mode = fi.Mode().Perm()
		}
		if err := os.WriteFile(filepath.Join(dir, "files", blob), data, 0o600); err != nil {
			return Checkpoint{}, err
		}
		cp.Files = append(cp.Files, BackedFile{Path: path, Blob: blob, Mode: mode})
	}
	sort.Slice(cp.Files, func(i, j int) bool { return cp.Files[i].Path < cp.Files[j].Path })

	meta, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return Checkpoint{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o600); err != nil {
		return Checkpoint{}, err
	}
	return cp, nil
}

// List returns all checkpoints, newest first.
func (s *Store) List() ([]Checkpoint, error) {
	entries, err := os.ReadDir(s.checkpointsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cps []Checkpoint
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if cp, err := s.Get(e.Name()); err == nil {
			cps = append(cps, cp)
		}
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i].CreatedAt.After(cps[j].CreatedAt) })
	return cps, nil
}

// Get loads one checkpoint by ID.
func (s *Store) Get(id string) (Checkpoint, error) {
	data, err := os.ReadFile(filepath.Join(s.checkpointsDir(), id, "meta.json"))
	if err != nil {
		return Checkpoint{}, err
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return Checkpoint{}, err
	}
	return cp, nil
}

// Rollback restores every backed-up file in a checkpoint to its original
// bytes and mode. It returns the checkpoint so the caller can surface any
// service restart the user should run.
func (s *Store) Rollback(id string) (Checkpoint, error) {
	cp, err := s.Get(id)
	if err != nil {
		return Checkpoint{}, err
	}
	if !cp.Reversible() {
		return cp, fmt.Errorf("checkpoint %s has no backed-up files to restore", id)
	}
	dir := filepath.Join(s.checkpointsDir(), id, "files")
	for _, bf := range cp.Files {
		data, err := os.ReadFile(filepath.Join(dir, bf.Blob))
		if err != nil {
			return cp, err
		}
		if err := os.WriteFile(bf.Path, data, bf.Mode); err != nil {
			return cp, err
		}
	}
	return cp, nil
}

// NewID returns a sortable checkpoint ID based on the current time and the
// finding it fixes.
func NewID(findingID string) string {
	return time.Now().UTC().Format("20060102-150405.000") + "-" + blobName(findingID)[:8]
}

// NewScanID returns a sortable ID for a scan snapshot.
func NewScanID() string {
	return time.Now().UTC().Format("20060102-150405.000")
}

// blobName returns a filesystem-safe name derived from a path.
func blobName(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}
