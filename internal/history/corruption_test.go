package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// savedCheckpoint applies one file's worth of backup and returns the store,
// the live path, and the checkpoint.
func savedCheckpoint(t *testing.T) (*Store, string, Checkpoint) {
	t.Helper()
	s := NewStore(t.TempDir())

	path := filepath.Join(t.TempDir(), "sshd_config")
	const original = "PermitRootLogin yes\nPasswordAuthentication yes\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	const applied = "PermitRootLogin no\nPasswordAuthentication yes\n"
	cp, err := s.Save(Checkpoint{
		ID: NewID("ssh.rootlogin"), FindingID: "ssh.rootlogin", Label: "Disable root login",
		CreatedAt: time.Now(), AppliedSHA256: map[string]string{path: SHA256Hex([]byte(applied))},
	}, map[string][]byte{path: []byte(original)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(applied), 0o600); err != nil {
		t.Fatal(err)
	}
	return s, path, cp
}

func blobPath(t *testing.T, s *Store, cp Checkpoint) string {
	t.Helper()
	if len(cp.Files) != 1 || cp.Files[0].Blob == "" {
		t.Fatalf("expected one backed-up file with a blob, got %+v", cp.Files)
	}
	return filepath.Join(s.checkpointsDir(), cp.ID, "files", cp.Files[0].Blob)
}

// The checkpoint is the only backup, so a damaged one must be refused rather
// than written over the live file. A blob truncated by a crash between the
// write returning and the data reaching disk — or by delayed allocation on
// XFS or btrfs — used to be restored as-is, and an empty sshd_config is the
// unrecoverable outcome the whole recovery layer exists to prevent.
func TestRollbackRefusesATruncatedBackup(t *testing.T) {
	s, path, cp := savedCheckpoint(t)
	live, _ := os.ReadFile(path)

	if err := os.WriteFile(blobPath(t, s, cp), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := s.Rollback(cp.ID)
	if err == nil {
		t.Fatal("rollback restored a zero-length backup over a live file")
	}
	if !strings.Contains(err.Error(), "damaged") {
		t.Errorf("the error should say the backup is damaged: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(live) {
		t.Errorf("the live file was modified by a refused rollback:\n%s", after)
	}
}

// Corruption that preserves the length is the case a size check would miss,
// which is why the guard is a hash.
func TestRollbackRefusesASilentlyCorruptedBackup(t *testing.T) {
	s, path, cp := savedCheckpoint(t)
	live, _ := os.ReadFile(path)

	bp := blobPath(t, s, cp)
	orig, err := os.ReadFile(bp)
	if err != nil {
		t.Fatal(err)
	}
	scrambled := append([]byte(nil), orig...)
	scrambled[0] ^= 0xff
	if err := os.WriteFile(bp, scrambled, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Rollback(cp.ID); err == nil {
		t.Fatal("rollback restored a corrupted backup of the same length")
	}
	if after, _ := os.ReadFile(path); string(after) != string(live) {
		t.Error("the live file was modified by a refused rollback")
	}
}

// force is for discarding the operator's later edits, not for restoring
// garbage. A damaged backup is not something --force should push through:
// there is nothing correct on the other side of it.
func TestForceDoesNotOverrideADamagedBackup(t *testing.T) {
	s, path, cp := savedCheckpoint(t)
	live, _ := os.ReadFile(path)

	if err := os.WriteFile(blobPath(t, s, cp), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RollbackForce(cp.ID); err == nil {
		t.Fatal("--force restored a damaged backup")
	}
	if after, _ := os.ReadFile(path); string(after) != string(live) {
		t.Error("the live file was modified by a refused forced rollback")
	}
}

// A blob written before BlobSHA256 existed has no hash. "Cannot tell" must
// not read as "corrupt", or upgrading would break rollback for every
// checkpoint already on disk.
func TestBackupsWithoutAHashStillRestore(t *testing.T) {
	s, path, cp := savedCheckpoint(t)

	// Strip the hash the way an older hostveil would have left it.
	cp.Files[0].BlobSHA256 = ""
	meta, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.checkpointsDir(), cp.ID, "meta.json"), meta, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Rollback(cp.ID); err != nil {
		t.Fatalf("a pre-upgrade checkpoint must still roll back: %v", err)
	}
	if after, _ := os.ReadFile(path); !strings.Contains(string(after), "PermitRootLogin yes") {
		t.Errorf("the original was not restored:\n%s", after)
	}
}

// An unreadable checkpoint used to vanish from the list with no message, so
// a fix that had genuinely been applied looked like it never was — and it
// also dropped out of recordedWrites, which can turn an honest rollback into
// a false external-edit refusal.
func TestUnreadableCheckpointIsReportedNotHidden(t *testing.T) {
	s, _, good := savedCheckpoint(t)

	broken := filepath.Join(s.checkpointsDir(), "20260101-000000.000-deadbeef-deadbeef")
	if err := os.MkdirAll(broken, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "meta.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	cps, err := s.List()
	if err == nil {
		t.Fatal("an unreadable checkpoint must be reported")
	}
	if !IsDamaged(err) {
		t.Errorf("the error should be a DamagedError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "20260101-000000.000-deadbeef-deadbeef") {
		t.Errorf("the warning should name the unreadable checkpoint: %v", err)
	}
	// The readable ones still come back — a partial list is useful, an empty
	// one is not.
	if len(cps) != 1 || cps[0].ID != good.ID {
		t.Errorf("the readable checkpoint should still be listed, got %+v", cps)
	}
}

// A store with nothing wrong reports nothing, or the warning means nothing.
func TestHealthyStoreReportsNoDamage(t *testing.T) {
	s, _, _ := savedCheckpoint(t)
	if _, err := s.List(); err != nil {
		t.Errorf("a healthy store must list cleanly, got %v", err)
	}
}

func TestGetRejectsCheckpointAndBlobPathTraversal(t *testing.T) {
	s, _, cp := savedCheckpoint(t)
	for _, id := range []string{"../outside", "a/b", ""} {
		if _, err := s.Get(id); err == nil {
			t.Errorf("Get accepted checkpoint id %q", id)
		}
	}

	cp.Files[0].Blob = "../outside"
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(s.checkpointsDir(), cp.ID, "meta.json")
	if err := os.WriteFile(meta, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(cp.ID); err == nil {
		t.Fatal("Get accepted a blob path outside the checkpoint")
	}
}

// Every new checkpoint carries a blob hash. Without this the guard above is
// dead code on real data.
func TestSaveRecordsTheBackupHash(t *testing.T) {
	s, _, cp := savedCheckpoint(t)
	if cp.Files[0].BlobSHA256 == "" {
		t.Fatal("Save did not record the backup's hash")
	}
	data, err := os.ReadFile(blobPath(t, s, cp))
	if err != nil {
		t.Fatal(err)
	}
	if SHA256Hex(data) != cp.Files[0].BlobSHA256 {
		t.Error("the recorded hash does not match the blob on disk")
	}
}

// A checkpoint directory with no meta.json is not a damaged checkpoint. It is
// the residue of a Save that never finished, and writeMeta's own comment says
// so: metadata is written last precisely so "an interrupted Save leaves a
// directory nothing will try to restore from".
//
// List tried anyway, and reported it as unreadable recovery history — a
// warning in all three UIs saying part of the operator's ability to undo is
// gone, when nothing was lost at all. Apply order is backup → write, so a
// Save that did not complete means the target file was never touched and
// there is nothing to undo.
//
// This is not only the crash case. Save returns on the first failed write —
// a full disk, EPERM, a read-only mount — applyEdit refuses to apply, and the
// partial directory stays on disk permanently, so every `hostveil history`
// from then on reports damage that no rollback could ever fix.
func TestAnInterruptedSaveIsNotDamagedHistory(t *testing.T) {
	store, _, good := savedCheckpoint(t)

	// Exactly what a Save interrupted after its blobs and before its metadata
	// leaves behind.
	partial := filepath.Join(store.checkpointsDir(), "20260101-000000.000-deadbeef-cafe", "files")
	if err := os.MkdirAll(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "blob"), []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cps, err := store.List()
	if err != nil {
		t.Errorf("an unfinished Save is not damage to report: %v", err)
	}
	if len(cps) != 1 || cps[0].ID != good.ID {
		t.Errorf("the readable checkpoint should be the only one listed, got %d: %+v", len(cps), cps)
	}
}

// The distinction that has to survive: metadata that exists and cannot be
// read *is* damage. Losing it means a fix that was applied can no longer be
// rolled back, and the operator has to be told.
func TestUnreadableMetadataIsStillDamage(t *testing.T) {
	store, _, cp := savedCheckpoint(t)

	meta := filepath.Join(store.checkpointsDir(), cp.ID, "meta.json")
	if err := os.WriteFile(meta, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(); !IsDamaged(err) {
		t.Errorf("corrupt metadata must still be reported: %v", err)
	}
}

// And Save cleans up after itself, so an ordinary failure does not leave
// residue for List to have to ignore in the first place. The directory it
// created is removed; one it found already there is left alone, because the
// checkpoint already in it is somebody's only copy.
func TestAFailedSaveLeavesNoDirectoryBehind(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
	store := NewStore(t.TempDir())
	id := NewID("compose.ds018")

	// A files/ directory the blob write cannot use. MkdirAll then succeeds
	// because it already exists, and WriteFileAtomic fails inside it — which
	// is the shape of a full disk or a read-only mount, reached here through
	// a permission bit instead.
	files := filepath.Join(store.checkpointsDir(), id, "files")
	if err := os.MkdirAll(files, 0o700); err != nil {
		t.Fatal(err)
	}
	// Only the leaf is made unwritable; MkdirAll would otherwise apply the
	// mode to the parents it creates and fail before Save ever runs.
	if err := os.Chmod(files, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(files, 0o700) })

	if _, err := store.Save(Checkpoint{ID: id, FindingID: "compose.ds018"},
		map[string][]byte{"/etc/ssh/sshd_config": []byte("x")}); err == nil {
		t.Fatal("the blob write should have failed")
	}
	if _, err := os.Stat(filepath.Join(store.checkpointsDir(), id)); !os.IsNotExist(err) {
		t.Errorf("a failed Save left its directory behind: %v", err)
	}
	if _, err := store.List(); err != nil {
		t.Errorf("and List then had something to complain about: %v", err)
	}
}

// The guard that matters more than the cleanup: a directory already holding a
// finished checkpoint is somebody's only backup, and a later Save that fails
// must not take it with it. IDs carry a random suffix so production never
// reuses one, but the cost of being wrong is unrecoverable.
func TestCleanupLeavesAFinishedCheckpointAlone(t *testing.T) {
	store, _, cp := savedCheckpoint(t)
	dir := filepath.Join(store.checkpointsDir(), cp.ID)

	discardUnfinished(dir, cp.ID)
	if _, err := store.Get(cp.ID); err != nil {
		t.Errorf("the finished checkpoint was removed: %v", err)
	}

	// And an empty ID is refused, because dir would then be the checkpoints
	// directory itself and this a RemoveAll of every backup on the host.
	discardUnfinished(store.checkpointsDir(), "")
	if _, err := store.Get(cp.ID); err != nil {
		t.Errorf("an empty ID wiped the whole store: %v", err)
	}
}
