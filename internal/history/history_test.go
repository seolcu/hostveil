package history

import (
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
