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
	// AppliedSHA256 maps each edited path to the SHA-256 of the content the
	// fix wrote. Rollback compares it against the file on disk to notice
	// that somebody edited the file afterwards.
	//
	// Without it, rollback overwrote whatever was there — so applying a fix
	// to sshd_config, hand-editing that file for an hour, then rolling back
	// destroyed the hour's work with no warning and no way to get it back,
	// because rollback writes no checkpoint of its own.
	//
	// Omitempty: checkpoints written before this field existed deserialize
	// to nil, and a nil entry means "cannot tell", which is not the same as
	// "unchanged" and must not be treated as consent.
	AppliedSHA256 map[string]string `json:"applied_sha256,omitempty"`
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

// ExternalEditError reports that a file changed after the fix wrote it, so
// rolling back would discard whatever was done to it in between.
//
// It is a distinct type rather than a plain error because every UI has to
// tell this apart from a genuine failure: the rollback did not fail, it
// declined, and the user can still choose to proceed.
type ExternalEditError struct {
	CheckpointID string
	Path         string
}

func (e *ExternalEditError) Error() string {
	return fmt.Sprintf("%s has changed since the fix was applied; rolling back would discard those edits "+
		"(re-run with --force to restore the backup anyway)", e.Path)
}

// checkUnmodified reports whether a file still holds content that hostveil
// itself wrote.
//
// The question is not "does this match what THIS fix wrote" — that would
// misfire on the most ordinary workflow there is. `fix --all` over two
// findings in one compose file applies two fixes to the same path in
// sequence, so by the time the first checkpoint is rolled back the file
// legitimately holds what the second fix wrote. Treating that as tampering
// would refuse a rollback nobody interfered with. (An existing test,
// TestRollbackUnmarksOnlyTheCheckpointedService, is exactly this shape and
// is what caught it.)
//
// So the test is membership: the file must hash to something some fix
// recorded writing. Anything else came from outside hostveil.
//
// A checkpoint from before AppliedSHA256 existed contributes no hashes, and
// a file that cannot be read yields no complaint — "cannot tell" must not be
// dressed up as either answer, and refusing every pre-upgrade checkpoint
// would break rollback for everyone updating.
func (s *Store) checkUnmodified(cp Checkpoint, bf BackedFile) error {
	if cp.AppliedSHA256[bf.Path] == "" {
		return nil // this checkpoint predates the recording; cannot tell
	}
	data, err := os.ReadFile(bf.Path) //nolint:gosec // path recorded by a fix this tool applied
	if err != nil {
		return nil
	}
	if s.writtenByHostveil(bf.Path, SHA256Hex(data)) {
		return nil
	}
	return &ExternalEditError{CheckpointID: cp.ID, Path: bf.Path}
}

// writtenByHostveil reports whether any checkpoint recorded writing exactly
// this content to this path.
func (s *Store) writtenByHostveil(path, sum string) bool {
	cps, err := s.List()
	if err != nil {
		// Unable to enumerate: allowing the rollback keeps the recovery path
		// working, and this only ever runs on a file the operator explicitly
		// asked to restore.
		return true
	}
	for _, c := range cps {
		if c.AppliedSHA256[path] == sum {
			return true
		}
	}
	return false
}

// SHA256Hex is exported so the engine can record what a fix wrote at the
// moment it writes it, using the same hash Rollback compares against.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Rollback restores every backed-up file in a checkpoint to its original
// bytes and mode, refusing if any of them changed after the fix wrote it.
// It returns the checkpoint so the caller can surface any service restart
// the user should run.
func (s *Store) Rollback(id string) (Checkpoint, error) {
	return s.rollback(id, false)
}

// RollbackForce restores the checkpoint even when a file changed after the
// fix wrote it. The caller is responsible for having told the user what
// they are discarding: rollback writes no checkpoint of its own, so this is
// one-way.
func (s *Store) RollbackForce(id string) (Checkpoint, error) {
	return s.rollback(id, true)
}

func (s *Store) rollback(id string, force bool) (Checkpoint, error) {
	cp, err := s.Get(id)
	if err != nil {
		return Checkpoint{}, err
	}
	if !cp.Reversible() {
		return cp, fmt.Errorf("checkpoint %s has no backed-up files to restore", id)
	}

	// Check every file before touching any of them. Rollback restores in a
	// loop and returns on the first error, so a mid-loop refusal would leave
	// some files restored and others not — a state neither the host nor the
	// in-memory report describes correctly.
	if !force {
		for _, bf := range cp.Files {
			if err := s.checkUnmodified(cp, bf); err != nil {
				return cp, err
			}
		}
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
