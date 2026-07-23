package history

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewIDIsUniquePerCall guards the checkpoint-ID collision directly.
// The timestamp resolves to a millisecond and the finding-hash suffix is
// constant per finding ID, so a batch fix applying the same finding to
// several services mints IDs in a tight loop like this one.
func TestNewIDIsUniquePerCall(t *testing.T) {
	const n = 1000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		id := NewID("compose.ds018")
		if seen[id] {
			t.Fatalf("duplicate checkpoint ID after %d calls: %s", i, id)
		}
		seen[id] = true
	}
}

// TestCollidingCheckpointsDoNotClobberBackups is the reason the ID has to
// be unique: checkpoints are the only backup mechanism, so two checkpoints
// sharing a directory means the second Save overwrites the first's blob
// with the already-modified file. Rolling back would then restore an
// intermediate state and the original bytes would be unrecoverable.
func TestCollidingCheckpointsDoNotClobberBackups(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	path := filepath.Join(dir, "docker-compose.yml")
	orig := []byte("services:\n  cache:\n    image: redis\n")
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}

	// Two fixes for the same finding ID against the same file, applied back
	// to back — the exact shape of a batch fix over several services.
	first, err := store.Save(Checkpoint{ID: NewID("compose.ds018"), FindingID: "compose.ds018"},
		map[string][]byte{path: orig})
	if err != nil {
		t.Fatal(err)
	}

	modified := []byte("services:\n  cache:\n    image: redis\n    read_only: true\n")
	if err := os.WriteFile(path, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := store.Save(Checkpoint{ID: NewID("compose.ds018"), FindingID: "compose.ds018"},
		map[string][]byte{path: modified})
	if err != nil {
		t.Fatal(err)
	}

	if first.ID == second.ID {
		t.Fatalf("both checkpoints got ID %s — the second clobbered the first", first.ID)
	}

	// Rolling the first checkpoint back must restore the true original, not
	// whatever the second checkpoint captured.
	if _, err := store.Rollback(first.ID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(orig) {
		t.Errorf("rollback restored the wrong bytes:\nwant:\n%s\ngot:\n%s", orig, got)
	}
}

func TestExecCheckpointIsNotReversible(t *testing.T) {
	store := NewStore(t.TempDir())
	cp, err := store.Save(Checkpoint{
		ID:        NewID("updates.disabled"),
		FindingID: "updates.disabled",
		Commands:  [][]string{{"systemctl", "enable", "unattended-upgrades"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Reversible() {
		t.Error("an exec checkpoint backs up no files and must not be reversible")
	}
	if _, err := store.Rollback(cp.ID); err == nil {
		t.Error("rolling back a non-reversible checkpoint should fail loudly")
	}
}

// TestListOrderIsDeterministicWithinAMillisecond: CreatedAt resolves to a
// millisecond, so a batch fix produces several checkpoints with an
// identical timestamp. sort.Slice is not stable, so without a tiebreak the
// history list would come back in a different order on each call and rows
// would appear to shuffle themselves under the cursor.
func TestListOrderIsDeterministicWithinAMillisecond(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Same finding ID and the same instant — exactly what `fix --all` over
	// several services produces.
	stamp := time.Now().UTC()
	for i := 0; i < 8; i++ {
		cp := Checkpoint{ID: NewID("compose.ds018"), FindingID: "compose.ds018", CreatedAt: stamp}
		if _, err := store.Save(cp, map[string][]byte{path: []byte("a\n")}); err != nil {
			t.Fatal(err)
		}
	}

	first, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 8 {
		t.Fatalf("want 8 checkpoints, got %d", len(first))
	}
	for i := 0; i < 20; i++ {
		again, err := store.List()
		if err != nil {
			t.Fatal(err)
		}
		for j := range first {
			if first[j].ID != again[j].ID {
				t.Fatalf("List order changed between calls at index %d: %s then %s",
					j, first[j].ID, again[j].ID)
			}
		}
	}
}

// TestListIsNewestFirst pins the ordering every UI's history view relies on.
func TestListIsNewestFirst(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	path := filepath.Join(dir, "f.conf")
	if err := os.WriteFile(path, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Save does not stamp CreatedAt — the engine does, at fixflow.go:189 —
	// so the test has to. Without it all three carried the zero time, the
	// assertion below was vacuously true, and the ordering was actually
	// being decided by the ID tiebreak. Flipping After to Before in List
	// left the whole suite green.
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	want := []string{"newest", "middle", "oldest"}
	for i, id := range []string{"oldest", "middle", "newest"} {
		cp := Checkpoint{
			ID:        NewID(id),
			FindingID: id,
			CreatedAt: base.Add(time.Duration(i) * time.Hour),
		}
		if _, err := store.Save(cp, map[string][]byte{path: []byte("a\n")}); err != nil {
			t.Fatal(err)
		}
	}

	cps, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 3 {
		t.Fatalf("want 3 checkpoints, got %d", len(cps))
	}
	for i, wantID := range want {
		if cps[i].FindingID != wantID {
			t.Errorf("position %d = %q, want %q — List must be newest first (got order %v)",
				i, cps[i].FindingID, wantID, findingIDs(cps))
		}
	}
	for i := 1; i < len(cps); i++ {
		if cps[i-1].CreatedAt.Before(cps[i].CreatedAt) {
			t.Errorf("checkpoint %d is older than %d — List must be newest first", i-1, i)
		}
	}
}

func findingIDs(cps []Checkpoint) []string {
	out := make([]string, len(cps))
	for i, c := range cps {
		out[i] = c.FindingID
	}
	return out
}

// NewScanID lacked the random suffix that NewID's own doc comment argues is
// mandatory, twelve lines above it. The timestamp resolves to a millisecond,
// so two scans starting within one produced the same filename and the second
// silently replaced the first — and the delta is computed from the newest
// snapshot, so a lost one makes the next scan compare against the wrong
// baseline.
func TestScanIDsAreUniqueWithinAMillisecond(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id := NewScanID()
		if seen[id] {
			t.Fatalf("NewScanID collided after %d calls: %q", i, id)
		}
		seen[id] = true
	}
}

// The timestamp must stay the prefix: scanFiles sorts lexically and treats
// that order as chronological, so a suffix that disturbed it would make
// LastReport return something other than the newest scan.
func TestScanIDsSortChronologically(t *testing.T) {
	first := NewScanID()
	time.Sleep(2 * time.Millisecond)
	second := NewScanID()
	if first >= second {
		t.Errorf("scan IDs must sort chronologically: %q should precede %q", first, second)
	}
}

// Two snapshots written in the same millisecond must both survive.
func TestConcurrentScanSnapshotsDoNotClobber(t *testing.T) {
	store := NewStore(t.TempDir())
	for i := 0; i < 5; i++ {
		if err := store.SaveReport(NewScanID(), []byte(`{"n":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	names, err := scanFiles(store.scansDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 5 {
		t.Errorf("wrote 5 snapshots, %d survived: %v", len(names), names)
	}
}

// Retention is executed on every save but nothing asserted it works, so a
// broken prune would grow the directory forever without a test noticing.
func TestScanSnapshotsArePrunedToMaxScans(t *testing.T) {
	store := NewStore(t.TempDir())
	for i := 0; i < maxScans+15; i++ {
		if err := store.SaveReport(NewScanID(), []byte(`{"n":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	names, err := scanFiles(store.scansDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != maxScans {
		t.Errorf("retained %d snapshots, want the %d cap", len(names), maxScans)
	}
	// The newest must be the survivors, not an arbitrary subset.
	if _, ok, err := store.LastReport(); err != nil || !ok {
		t.Errorf("LastReport after pruning: ok=%v err=%v", ok, err)
	}
}

// Rollback used to overwrite whatever was on disk with no checks at all: no
// hash, no mtime, not even an existence test. Apply a fix to sshd_config,
// hand-edit it for an hour, roll back — and the hour was gone, permanently,
// because rollback writes no checkpoint of its own.
func TestRollbackRefusesToDiscardExternalEdits(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	path := filepath.Join(dir, "sshd_config")

	orig := []byte("PermitRootLogin yes\n")
	applied := []byte("PermitRootLogin no\n")
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	cp, err := store.Save(Checkpoint{
		ID:            NewID("ssh.rootlogin"),
		FindingID:     "ssh.rootlogin",
		AppliedSHA256: map[string]string{path: SHA256Hex(applied)},
	}, map[string][]byte{path: orig})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, applied, 0o600); err != nil {
		t.Fatal(err)
	}

	// Untouched since the fix: rollback proceeds.
	if _, err := store.Rollback(cp.ID); err != nil {
		t.Fatalf("an unmodified file should roll back cleanly: %v", err)
	}

	// Now the operator edits the file after the fix.
	if err := os.WriteFile(path, applied, 0o600); err != nil {
		t.Fatal(err)
	}
	edited := []byte("PermitRootLogin no\nAllowUsers alice\n")
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = store.Rollback(cp.ID)
	var ext *ExternalEditError
	if !errors.As(err, &ext) {
		t.Fatalf("want ExternalEditError, got %v", err)
	}
	if ext.Path != path {
		t.Errorf("error names %q, want %q", ext.Path, path)
	}
	// Declining must change nothing.
	if got, _ := os.ReadFile(path); string(got) != string(edited) {
		t.Errorf("a refused rollback modified the file:\n%s", got)
	}

	// Force is the escape hatch, and it really does discard.
	if _, err := store.RollbackForce(cp.ID); err != nil {
		t.Fatalf("force: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(orig) {
		t.Errorf("force should restore the original:\nwant %q\ngot  %q", orig, got)
	}
}

// Two fixes to the same file in sequence — what `fix --all` does with two
// findings in one compose file — must not look like tampering. By the time
// the first checkpoint is rolled back the file holds what the SECOND fix
// wrote, which hostveil is responsible for.
func TestSequentialFixesToOneFileAreNotTampering(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	path := filepath.Join(dir, "docker-compose.yml")

	v0 := []byte("a\n")
	v1 := []byte("b\n")
	v2 := []byte("c\n")
	if err := os.WriteFile(path, v0, 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := store.Save(Checkpoint{
		ID: NewID("compose.ds018"), FindingID: "compose.ds018",
		AppliedSHA256: map[string]string{path: SHA256Hex(v1)},
	}, map[string][]byte{path: v0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(Checkpoint{
		ID: NewID("compose.dr002"), FindingID: "compose.dr002",
		AppliedSHA256: map[string]string{path: SHA256Hex(v2)},
	}, map[string][]byte{path: v1}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, v2, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Rollback(first.ID); err != nil {
		t.Errorf("a second hostveil fix is not an external edit: %v", err)
	}
}

// A checkpoint written before AppliedSHA256 existed records no hash. That is
// "cannot tell", and refusing every such rollback would break recovery for
// anyone upgrading — so it proceeds, as it always did.
func TestOldCheckpointsWithoutHashesStillRollBack(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	path := filepath.Join(dir, "f.conf")
	if err := os.WriteFile(path, []byte("orig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cp, err := store.Save(Checkpoint{ID: NewID("x.y"), FindingID: "x.y"},
		map[string][]byte{path: []byte("orig\n")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("edited by hand\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rollback(cp.ID); err != nil {
		t.Errorf("a pre-upgrade checkpoint must still roll back: %v", err)
	}
}

// Checkpoints are backups, so they are capped far more loosely than scan
// snapshots — but they are capped. Nothing removed them before, and each
// holds a full copy of every file its fix touched, so a long-lived host grew
// its state directory without bound and paid for it on every history view.
func TestCheckpointsArePrunedOldestFirst(t *testing.T) {
	s := NewStore(t.TempDir())

	total := maxCheckpoints + 10
	ids := make([]string, 0, total)
	for i := range total {
		cp := Checkpoint{
			ID:        fmt.Sprintf("2026%06d-000000.000-aaaaaaaa-0000000%d", i, i%10),
			FindingID: "ssh.rootlogin",
			CreatedAt: time.Unix(int64(i), 0).UTC(),
		}
		saved, err := s.Save(cp, map[string][]byte{
			filepath.Join(t.TempDir(), "f"): []byte("contents"),
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, saved.ID)
	}

	kept, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != maxCheckpoints {
		t.Errorf("kept %d checkpoints, want the cap of %d", len(kept), maxCheckpoints)
	}

	// The newest must survive: pruning from that end would strip the record
	// the external-edit check reads, making a rollback of an untouched file
	// look like tampering.
	newest := ids[len(ids)-1]
	if _, err := s.Get(newest); err != nil {
		t.Errorf("the newest checkpoint was pruned: %v", err)
	}
	if _, err := s.Get(ids[0]); err == nil {
		t.Error("the oldest checkpoint survived the cap")
	}
}

// A batch fix must not prune the backups it is in the middle of writing:
// a checkpoint discarded moments after it was created is a fix that became
// unrollbackable the instant it was applied.
func TestOneBatchFitsUnderTheCheckpointCap(t *testing.T) {
	s := NewStore(t.TempDir())
	dir := t.TempDir()

	// Comfortably more findings than any single `fix --all` produces.
	const batch = 60
	for i := range batch {
		path := filepath.Join(dir, fmt.Sprintf("f%d", i))
		if err := os.WriteFile(path, []byte("orig"), 0o600); err != nil {
			t.Fatal(err)
		}
		cp := Checkpoint{ID: NewID("compose.ds018"), FindingID: "compose.ds018", CreatedAt: time.Now()}
		if _, err := s.Save(cp, map[string][]byte{path: []byte("orig")}); err != nil {
			t.Fatal(err)
		}
	}

	kept, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != batch {
		t.Errorf("a %d-fix batch left %d checkpoints; every one must survive its own session", batch, len(kept))
	}
}
