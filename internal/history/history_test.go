package history

import (
	"os"
	"path/filepath"
	"testing"
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

// TestListIsNewestFirst pins the ordering every UI's history view relies on.
func TestListIsNewestFirst(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	path := filepath.Join(dir, "f.conf")
	if err := os.WriteFile(path, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"ssh.rootlogin", "compose.ds006", "ssh.maxauthtries"} {
		if _, err := store.Save(Checkpoint{ID: NewID(id), FindingID: id}, map[string][]byte{path: []byte("a\n")}); err != nil {
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
	for i := 1; i < len(cps); i++ {
		if cps[i-1].CreatedAt.Before(cps[i].CreatedAt) {
			t.Errorf("checkpoint %d is older than %d — List must be newest first", i-1, i)
		}
	}
}
