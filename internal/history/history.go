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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/platform"
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
	// BlobSHA256 is the hash of the backup itself, checked before the blob is
	// written back over a live file.
	//
	// AppliedSHA256 on the Checkpoint records what the fix *wrote* and answers
	// a different question — has the operator edited this since? Nothing
	// recorded what was *backed up*, so a blob that was truncated by a crash
	// between the write returning and the data reaching disk, or by delayed
	// allocation on XFS or btrfs, was restored as-is. Writing an empty
	// /etc/ssh/sshd_config over a working one is precisely the unrecoverable
	// outcome the whole recovery layer exists to prevent.
	//
	// Omitempty: blobs written before this field existed have no hash, and a
	// missing hash means "cannot tell", which must not read as either answer —
	// see verifyBlob.
	BlobSHA256 string `json:"blob_sha256,omitempty"`

	// Created records that the fix brought this file into existence, so
	// restoring it means deleting it rather than writing something back.
	//
	// It is an explicit flag rather than an inference from an empty Blob,
	// because an empty Blob already means something else — SaveModes writes
	// mode-only entries with no blob, and those must be left alone. Guessing
	// between "no contents were touched" and "there were no contents" would
	// make rollback delete a file whose permissions were the only thing a
	// fix ever changed.
	Created bool `json:"created,omitempty"`
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
		// Atomic and fsync'ed, like every other write here. This is a backup
		// being taken moments before the file it copies is overwritten; if the
		// crash that makes the backup matter is also the crash that leaves it
		// half-written, the recovery layer has recorded a promise it cannot
		// keep.
		if err := platform.WriteFileAtomic(filepath.Join(dir, "files", blob), data, 0o600); err != nil {
			discardUnfinished(dir, cp.ID)
			return Checkpoint{}, err
		}
		cp.Files = append(cp.Files, BackedFile{
			Path: path, Blob: blob, Mode: mode, BlobSHA256: SHA256Hex(data),
		})
	}
	sort.Slice(cp.Files, func(i, j int) bool { return cp.Files[i].Path < cp.Files[j].Path })

	if err := s.writeMeta(dir, cp); err != nil {
		discardUnfinished(dir, cp.ID)
		return Checkpoint{}, err
	}
	s.pruneCheckpoints()
	return cp, nil
}

// Discard removes a finished checkpoint whose fix then failed to land.
//
// It is the narrow counterpart to discardUnfinished, which handles a Save that
// never completed. This one handles the opposite order: the backup succeeded,
// the write did not, and what is left describes a change the host never
// received. Keeping it would put a reversible applied fix in `hostveil
// history` for something that never happened, and — worse — leave its
// AppliedSHA256 asserting to recordedWrites that hostveil wrote bytes it did
// not, which weakens the external-edit guard for that path from then on.
//
// The caller must be sure the host is unchanged. Nothing here can check that,
// which is why this is not exported as anything more general than its one use.
func (s *Store) Discard(id string) error {
	if id == "" {
		return errors.New("refusing to discard an empty checkpoint id")
	}
	return os.RemoveAll(filepath.Join(s.checkpointsDir(), id))
}

// discardUnfinished removes the directory of a Save that could not complete,
// so an ordinary failure leaves nothing for List to have to recognise and
// ignore.
//
// Two guards, both of them about not destroying somebody's only backup:
//
//   - A directory already holding a meta.json is a finished checkpoint. IDs
//     carry a random suffix so production never reuses one, but a caller that
//     did would otherwise have the earlier checkpoint deleted by the later
//     Save's failure.
//   - An empty ID is refused outright. dir is checkpointsDir()/cp.ID, so an
//     empty one makes this a RemoveAll of every checkpoint on the host. The
//     call could not reach here with one today; the cost of being wrong about
//     that is the entire recovery history.
func discardUnfinished(dir, id string) {
	if id == "" {
		return
	}
	if _, err := os.Stat(filepath.Join(dir, "meta.json")); err == nil {
		return
	}
	_ = os.RemoveAll(dir)
}

// writeMeta persists the checkpoint's metadata, last and atomically.
//
// Order matters: meta.json is what List and Get read, so a checkpoint exists
// exactly when its metadata does. Writing it after the blobs means an
// interrupted Save leaves a directory nothing will try to restore from,
// rather than a checkpoint that promises files it never finished copying.
func (s *Store) writeMeta(dir string, cp Checkpoint) error {
	meta, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	return platform.WriteFileAtomic(filepath.Join(dir, "meta.json"), meta, 0o600)
}

// maxCheckpoints caps how many restore points are kept.
//
// Unlike a scan snapshot, a checkpoint is a backup: discarding one discards
// the ability to undo the fix that wrote it, so this cap is deliberately
// far looser than maxScans. It exists because checkpoints hold a full copy
// of every file a fix touched and nothing ever removed them — a long-lived
// host accumulated backups until the state directory was the problem, and
// List() reads and parses every one of them on each history view and each
// rollback.
//
// It bounds how far back the history goes; minRetention, not this number, is
// what keeps a fix rollbackable after it is applied.
const maxCheckpoints = 200

// minRetention is how long a checkpoint is held back from maxCheckpoints.
//
// The count cap cannot express the guarantee that matters. pruneCheckpoints
// runs on every save, so a `fix --all` writing more than maxCheckpoints in one
// run pruned its own earliest checkpoints: the fixes it applied first became
// unrollbackable the instant they were applied, which is the one thing the cap
// exists to avoid. The cap used to answer that by being "a big enough number",
// which is a hope and not a mechanism — no-new-privileges and a missing
// restart policy are both Auto and both fire on nearly every stock compose
// service, so a host with a hundred services reaches 200 in a single batch.
//
// A duration says it directly: nothing written recently is discarded, however
// much arrived at once. That also covers the cases a per-batch rule would
// miss — fixes applied one at a time from the dashboard, or a shell loop over
// `hostveil fix` — where each is equally rollbackable-then-not.
//
// An hour spans any one run plus the window in which an operator notices the
// host misbehaving and reaches for rollback. Growth stays bounded by what can
// be applied inside it.
const minRetention = time.Hour

// idTimeLayout is the timestamp prefix NewID and NewScanID mint, and both of
// them format through it rather than restating it — which they used to do,
// leaving three copies of one layout across two files while this constant's
// own comment claimed to be what they wrote.
//
// The stakes are not equal on the two sides. A scan id that stops parsing
// empties the trend, quietly. A *checkpoint* id that stops parsing makes every
// checkpoint undatable, and pruneCheckpoints treats undatable as prunable — so
// minRetention, the guarantee that a fix stays rollbackable however many
// arrive at once, would evaporate without a single error.
//
// Pruning reads an ID's age straight out of the directory name through this,
// which is what keeps that path free of meta.json reads.
const idTimeLayout = "20060102-150405.000"

// idTime recovers when an ID was minted from its timestamp prefix.
//
// ok is false for anything it cannot date — an ID from a format that predates
// this one, or a stray directory. Such an entry is treated as prunable rather
// than protected: the guarantee below is for checkpoints this build wrote, and
// an undatable one must not become immortal for want of a timestamp.
func idTime(id string) (time.Time, bool) {
	if len(id) < len(idTimeLayout) {
		return time.Time{}, false
	}
	at, err := time.ParseInLocation(idTimeLayout, id[:len(idTimeLayout)], time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

// pruneCheckpoints removes restore points beyond maxCheckpoints that are also
// older than minRetention. Both conditions must hold: the count is what bounds
// the directory, the age is what keeps a fix rollbackable after it is applied.
//
// Oldest-first is what makes this safe against the external-edit check.
// That check asks whether a file still holds content *some* checkpoint
// recorded writing, so the entry that matters for a path is the most recent
// one. Pruning from the other end would strip the newest record and make a
// rollback of an untouched file look like tampering.
//
// Ordering comes from the directory names alone. IDs are timestamp-prefixed
// (see NewID), so a lexical sort is chronological — the same property
// scanFiles relies on. Going through List() instead would read and JSON-parse
// every checkpoint on disk on *every* fix applied, turning a batch fix into a
// quadratic pile of reads; the cheap path is the whole point of pruning here.
//
// A failure to prune is not a failure to apply a fix: the checkpoint is
// already written, the host is already changed, and refusing here would
// report an error for a fix that succeeded.
func (s *Store) pruneCheckpoints() {
	dir := s.checkpointsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) <= maxCheckpoints {
		return
	}
	sort.Strings(names) // oldest first
	cutoff := time.Now().UTC().Add(-minRetention)
	for _, name := range names[:len(names)-maxCheckpoints] {
		// Reaching something recent ends the sweep rather than skipping it:
		// names are in chronological order, so everything left is newer still.
		if at, ok := idTime(name); ok && at.After(cutoff) {
			return
		}
		_ = os.RemoveAll(filepath.Join(dir, name))
	}
}

// SaveModes writes a checkpoint that restores permissions only. modes maps
// each path to the mode it had before the fix ran.
//
// It is the counterpart to Save for fixes that change a file's mode without
// changing its bytes. The resulting checkpoint is Reversible — Files is
// non-empty — but stores no blobs.
func (s *Store) SaveModes(cp Checkpoint, modes map[string]os.FileMode) (Checkpoint, error) {
	files := make([]BackedFile, 0, len(modes))
	for path, mode := range modes {
		files = append(files, BackedFile{Path: path, Mode: mode})
	}
	return s.saveBlobless(cp, files)
}

// SaveCreations writes a checkpoint for a fix that created files which did
// not exist before. paths names them; restoring the checkpoint deletes them.
//
// It is the third sibling of Save and SaveModes, and it exists for the same
// reason SaveModes does: the checkpoint has to describe what undoing this
// fix means, and "write these bytes back" cannot describe a file that had
// no bytes. There is nothing to back up — that is the whole point — so the
// checkpoint stores no blobs and is Reversible on the strength of naming
// the paths.
//
// A fix that both creates one file and edits another would need Save and
// this at once, and cannot express it. No such fix exists: an Action
// carries a single Path. If one is ever written, this is where it breaks,
// loudly, rather than silently checkpointing half of it.
func (s *Store) SaveCreations(cp Checkpoint, paths []string) (Checkpoint, error) {
	files := make([]BackedFile, 0, len(paths))
	for _, path := range paths {
		files = append(files, BackedFile{Path: path, Created: true})
	}
	return s.saveBlobless(cp, files)
}

// saveBlobless writes a checkpoint whose entries name paths and carry no
// backed-up bytes — the shared body of SaveModes and SaveCreations, which
// differ only in the BackedFile they build.
//
// It is one function rather than two identical ones because the order here is
// load-bearing and belongs in a single place: the metadata file is written
// last, so a checkpoint exists exactly when its metadata does, and a failed
// write takes the half-built directory with it rather than leaving something
// List would later report as damaged. Two copies of that is two chances for
// the next edit to land in one of them.
func (s *Store) saveBlobless(cp Checkpoint, files []BackedFile) (Checkpoint, error) {
	dir := filepath.Join(s.checkpointsDir(), cp.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Checkpoint{}, err
	}

	cp.Files = files
	sort.Slice(cp.Files, func(i, j int) bool { return cp.Files[i].Path < cp.Files[j].Path })

	if err := s.writeMeta(dir, cp); err != nil {
		discardUnfinished(dir, cp.ID)
		return Checkpoint{}, err
	}
	s.pruneCheckpoints()
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
	var damaged []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cp, err := s.Get(e.Name())
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// No meta.json at all: this was never a checkpoint. writeMeta
			// writes the metadata last precisely so an interrupted Save leaves
			// a directory nothing will try to restore from — and since apply
			// order is backup → write, a Save that did not finish means the
			// target file was never touched and there is nothing to undo.
			//
			// Reporting it as damage said the opposite: every UI warned that
			// part of the operator's ability to roll back was gone, over a
			// directory whose absence would have changed nothing. And it did
			// not take a crash. Save returns on its first failed write — a
			// full disk, EPERM, a read-only mount — and the residue then sat
			// there permanently, so every later `hostveil history` repeated a
			// warning no rollback could ever clear.
			continue
		case err != nil:
			// Metadata that exists and cannot be read is different, and is
			// real damage: a fix that *was* applied can no longer be rolled
			// back. Dropping it silently made that fix vanish from `hostveil
			// history` with no message and no way to tell it had ever been
			// applied — and it also fell out of recordedWrites, which can turn
			// an honest rollback into a false "the file was edited externally"
			// refusal.
			damaged = append(damaged, e.Name())
			continue
		}
		cps = append(cps, cp)
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
	if len(damaged) > 0 {
		// Returned alongside the readable checkpoints, not instead of them: the
		// list is still useful and the operator still needs to be told that
		// part of their recovery history is unreadable.
		sort.Strings(damaged)
		return cps, &DamagedError{IDs: damaged}
	}
	return cps, nil
}

// DamagedError reports checkpoints whose metadata could not be read. It
// accompanies a successful List rather than replacing it — callers that only
// want to render the history can ignore it, and callers that report problems
// can surface it.
type DamagedError struct{ IDs []string }

func (e *DamagedError) Error() string {
	return fmt.Sprintf("%d checkpoint(s) are unreadable and cannot be rolled back: %s",
		len(e.IDs), strings.Join(e.IDs, ", "))
}

// IsDamaged reports whether err is the unreadable-checkpoint warning. It
// exists so a caller can tell "the list is incomplete" from "the list
// failed", which matters because the first still carries usable entries.
func IsDamaged(err error) bool {
	var d *DamagedError
	return errors.As(err, &d)
}

// Get loads one checkpoint by ID.
func (s *Store) Get(id string) (Checkpoint, error) {
	// G304: the variable is a checkpoint ID, joined under the store's own
	// directory. It reaches here from a UI that got it out of List, so it
	// names something this process wrote — and the read is of hostveil's own
	// state, not of anything the ID could point at outside it.
	//nolint:gosec // G304: a checkpoint ID under the store's own directory
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
// itself wrote, given the set of writes every checkpoint has recorded.
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
func checkUnmodified(cp Checkpoint, bf BackedFile, known recordedWrites) error {
	if cp.AppliedSHA256[bf.Path] == "" {
		return nil // this checkpoint predates the recording; cannot tell
	}
	data, err := os.ReadFile(bf.Path) // path recorded by a fix this tool applied
	if err != nil {
		return nil
	}
	if known.has(bf.Path, SHA256Hex(data)) {
		return nil
	}
	return &ExternalEditError{CheckpointID: cp.ID, Path: bf.Path}
}

// recordedWrites maps each path to every content hash some checkpoint
// recorded writing to it. A nil map means the checkpoints could not be
// enumerated, which reads as "cannot tell" rather than "tampered with".
type recordedWrites map[string]map[string]bool

func (w recordedWrites) has(path, sum string) bool {
	if w == nil {
		// Unable to enumerate: allowing the rollback keeps the recovery path
		// working, and this only ever runs on a file the operator explicitly
		// asked to restore.
		return true
	}
	return w[path][sum]
}

// recordedWrites builds the index once.
//
// It exists because the check is per-file and used to re-List() — reading and
// JSON-parsing every checkpoint on disk — for each file in the checkpoint
// being restored. That is O(checkpoints × files) reads to answer a question
// with one pass, on a directory that only ever grows.
func (s *Store) recordedWrites() recordedWrites {
	cps, err := s.List()
	// An incomplete index is worse than none. Membership is the whole test —
	// the file must hash to something *some* fix recorded writing — so a
	// missing checkpoint turns an honest rollback into a false "you edited
	// this externally" refusal. nil reads as "cannot tell", which allows the
	// restore the operator explicitly asked for.
	if err != nil {
		return nil
	}
	out := recordedWrites{}
	for _, c := range cps {
		for path, sum := range c.AppliedSHA256 {
			if out[path] == nil {
				out[path] = map[string]bool{}
			}
			out[path][sum] = true
		}
	}
	return out
}

// SHA256Hex is exported so the engine can record what a fix wrote at the
// moment it writes it, using the same hash Rollback compares against.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// verifyBlob refuses to restore a backup that is not the backup that was
// taken.
//
// A blob with no recorded hash predates the field and is restored as before:
// "cannot tell" must not be dressed up as either answer, and refusing every
// pre-upgrade checkpoint would break rollback for everyone updating — the
// same rule checkUnmodified follows. New checkpoints always carry one.
func verifyBlob(bf BackedFile, data []byte) error {
	if bf.BlobSHA256 == "" || SHA256Hex(data) == bf.BlobSHA256 {
		return nil
	}
	return fmt.Errorf("the backup of %s is damaged (%d bytes, wrong checksum); "+
		"restoring it would overwrite the live file with corrupt data", bf.Path, len(data))
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
		known := s.recordedWrites()
		for _, bf := range cp.Files {
			if err := checkUnmodified(cp, bf, known); err != nil {
				return cp, err
			}
		}
	}

	// Read and verify every blob before writing any of them, for the same
	// reason the external-edit check runs up front: a restore that fails
	// half-way leaves some files restored and others not, which is a state
	// neither the host nor the in-memory report describes correctly.
	dir := filepath.Join(s.checkpointsDir(), id, "files")
	blobs := make(map[string][]byte, len(cp.Files))
	for _, bf := range cp.Files {
		if bf.Blob == "" {
			continue // mode-only entry; the contents were never touched
		}
		// G304: a blob name out of the checkpoint's own metadata, joined
		// under that checkpoint's directory. Both were written by Save.
		//nolint:gosec // G304: a blob this store wrote, in its own directory
		data, err := os.ReadFile(filepath.Join(dir, bf.Blob))
		if err != nil {
			return cp, err
		}
		if err := verifyBlob(bf, data); err != nil {
			return cp, err
		}
		blobs[bf.Path] = data
	}

	// Past this point the host is being written to, and the pre-flight above
	// exists because a restore that stops half-way is a state neither the
	// host nor the report describes. The pre-flight cannot make that
	// impossible — a disk can fill, a file can vanish between the check and
	// the write — so what is left is to finish the ones that can be finished
	// and say exactly which those were.
	//
	// Returning on the first error, which this did, left the earlier paths
	// restored, the later ones untouched, and the caller holding nothing but
	// an error: Engine.rollback discarded the checkpoint, so no interface
	// could name a single file that had moved.
	var restored, failed []string
	var errs []error
	for _, bf := range cp.Files {
		// The file did not exist before the fix, so restoring it means
		// removing it. An already-absent file is the desired end state, not
		// an error — an operator who deleted the drop-in by hand and then
		// rolled back should get success, not a failure describing the thing
		// they already did.
		//
		// This runs after the same external-edit check every other entry
		// gets, so a drop-in the operator has since edited declines here
		// rather than being deleted out from under them.
		if bf.Created {
			if err := os.Remove(bf.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				failed, errs = append(failed, bf.Path), append(errs, err)
				continue
			}
			restored = append(restored, bf.Path)
			continue
		}
		// A mode-only entry carries no blob: the fix changed permissions and
		// never touched the contents, so there is nothing to write back.
		if data, ok := blobs[bf.Path]; ok {
			// Atomically, because this is the write that runs when something
			// has already gone wrong. os.WriteFile truncates first, so an
			// interrupted restore destroys the very file it was recovering —
			// and rollback keeps no backup of its own to try again from.
			if err := platform.WriteFileAtomic(bf.Path, data, bf.Mode); err != nil {
				failed, errs = append(failed, bf.Path), append(errs, err)
				continue
			}
		}
		// os.WriteFile applies its perm argument only when it creates the
		// file, so restoring the mode of a file that still exists needs an
		// explicit chmod. Without this the Mode recorded on every checkpoint
		// was never applied to anything.
		//
		// No-follow, because mode-only checkpoints point into user homes
		// (agent.config-perms) and the account that owns the path can have
		// replaced it with a symlink since the fix ran — os.Chmod would carry
		// root's chmod through to the link's target.
		// A file that is no longer there is the same situation the Created
		// branch above tolerates deliberately: the operator removed it, and
		// failing to set the mode of something that does not exist is not a
		// failure to restore it.
		if err := platform.ChmodNoFollow(bf.Path, bf.Mode); err != nil && !errors.Is(err, fs.ErrNotExist) {
			failed, errs = append(failed, bf.Path), append(errs, err)
			continue
		}
		restored = append(restored, bf.Path)
	}
	if len(errs) > 0 {
		return cp, &PartialRestoreError{Restored: restored, Failed: failed, Err: errors.Join(errs...)}
	}
	return cp, nil
}

// PartialRestoreError reports a rollback that wrote some of a checkpoint's
// files and not others.
//
// It exists so the answer to "what state is my host in now" is in the error
// rather than absent from it. Rollback keeps no backup of its own, so there
// is nothing to retry from automatically and nothing to undo — which makes
// naming the two halves the only useful thing left to do.
type PartialRestoreError struct {
	Restored []string
	Failed   []string
	Err      error
}

func (e *PartialRestoreError) Error() string {
	return fmt.Sprintf("restored %d of %d files; %d could not be written (%s): %v",
		len(e.Restored), len(e.Restored)+len(e.Failed), len(e.Failed),
		strings.Join(e.Failed, ", "), e.Err)
}

func (e *PartialRestoreError) Unwrap() error { return e.Err }

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
	return time.Now().UTC().Format(idTimeLayout) + "-" + blobName(findingID)[:8] + "-" + randomSuffix()
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
	return time.Now().UTC().Format(idTimeLayout) + "-" + randomSuffix()
}

// blobName returns a filesystem-safe name derived from a path.
func blobName(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

// RetentionPolicy reports how many checkpoints are kept and how long a recent
// one is held back from that cap.
//
// Exported so the published documentation can be pinned against these two
// numbers rather than restating them and drifting. "How far back can I roll
// back?" is a question a user is entitled to a written answer to, and a
// written answer that has gone stale is worse than none.
func RetentionPolicy() (count int, window time.Duration) {
	return maxCheckpoints, minRetention
}
