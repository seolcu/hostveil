// Package history is hostveil's recovery layer: before any fix changes a
// file, the engine backs the original up here as a checkpoint, so any
// applied change — made from any UI — can be rolled back with one command.
// The checkpoint is the ONLY backup mechanism, which is what makes
// cross-UI rollback correct.
package history

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// BackedFile records one file captured in a checkpoint.
//
// Blob is empty for a mode-only entry, written when a fix changed a file's
// permissions without touching its contents. Copying the bytes anyway would
// mean spilling the contents of files like /etc/shadow into the checkpoint
// directory to undo a chmod — a second copy of every password hash, to
// restore nine bits.
type BackedFile struct {
	Path string      `json:"path"` // original absolute path
	Blob string      `json:"blob,omitempty"`
	Mode os.FileMode `json:"mode"`
}

// Checkpoint is a restore point created when a fix is applied.
type Checkpoint struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
	// FindingKey is the finding's full source|id|service key, which is what
	// identifies it uniquely — FindingID alone collides across services
	// (two exposed datastores share an ID). Rollback needs it to un-mark the
	// right finding. Omitempty: checkpoints written before this field
	// existed deserialize to "" and fall back to matching on FindingID.
	FindingKey     string       `json:"finding_key,omitempty"`
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

// SaveModes writes a checkpoint that restores permissions only. modes maps
// each path to the mode it had before the fix ran.
//
// It is the counterpart to Save for fixes that change a file's mode without
// changing its bytes. The resulting checkpoint is Reversible — Files is
// non-empty — but stores no blobs.
func (s *Store) SaveModes(cp Checkpoint, modes map[string]os.FileMode) (Checkpoint, error) {
	dir := filepath.Join(s.checkpointsDir(), cp.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Checkpoint{}, err
	}

	cp.Files = cp.Files[:0]
	for path, mode := range modes {
		cp.Files = append(cp.Files, BackedFile{Path: path, Mode: mode})
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
	// Newest first, breaking ties on ID. CreatedAt resolves to a
	// millisecond, so a batch fix produces several checkpoints with the same
	// timestamp; without a tiebreak sort.Slice (which is not stable) would
	// order the history list differently on each call.
	sort.Slice(cps, func(i, j int) bool {
		if !cps[i].CreatedAt.Equal(cps[j].CreatedAt) {
			return cps[i].CreatedAt.After(cps[j].CreatedAt)
		}
		return cps[i].ID > cps[j].ID
	})
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
		// A mode-only entry carries no blob: the fix changed permissions and
		// never touched the contents, so there is nothing to write back.
		if bf.Blob != "" {
			data, err := os.ReadFile(filepath.Join(dir, bf.Blob))
			if err != nil {
				return cp, err
			}
			if err := os.WriteFile(bf.Path, data, bf.Mode); err != nil {
				return cp, err
			}
		}
		// os.WriteFile applies its perm argument only when it creates the
		// file, so restoring the mode of a file that still exists needs an
		// explicit chmod. Without this the Mode recorded on every checkpoint
		// was never applied to anything.
		if err := os.Chmod(bf.Path, bf.Mode); err != nil {
			return cp, err
		}
	}
	return cp, nil
}

// NewID returns a sortable checkpoint ID based on the current time and the
// finding it fixes.
//
// The trailing random component is load-bearing, not decoration. The
// timestamp resolves to a millisecond and the finding hash is constant for
// a given finding ID, so without it a batch fix that raises the same
// finding for several services (three exposed datastores in one compose
// file, say) mints one ID for all of them. Colliding IDs share a
// checkpoint directory, so each Save overwrites the previous backup with
// the already-modified file — the original bytes are lost and rollback
// restores an intermediate state. Checkpoints are the only backup there
// is, so an ID collision is silent data loss.
func NewID(findingID string) string {
	return time.Now().UTC().Format("20060102-150405.000") + "-" + blobName(findingID)[:8] + "-" + randomSuffix()
}

// randomSuffix returns 4 bytes of hex. On the (practically impossible)
// failure of the system CSPRNG it falls back to the nanosecond clock,
// which still separates same-millisecond checkpoints.
func randomSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano()%0xffffffff, 16)
	}
	return hex.EncodeToString(b[:])
}

// NewScanID returns a sortable ID for a scan snapshot.
//
// It carries the same random suffix as NewID, and for the same reason: the
// timestamp resolves to a millisecond, so two scans starting within one
// wrote to the same filename and the second silently replaced the first.
// The delta between scans is computed from the newest snapshot, so a lost
// one makes the next scan compare against the wrong baseline.
//
// The timestamp stays the prefix, so scanFiles' lexical sort remains
// chronological. Within a single millisecond the order becomes arbitrary,
// which is the correct answer for two events at the same instant and is in
// any case better than one of them not existing.
func NewScanID() string {
	return time.Now().UTC().Format("20060102-150405.000") + "-" + randomSuffix()
}

// blobName returns a filesystem-safe name derived from a path.
func blobName(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}
