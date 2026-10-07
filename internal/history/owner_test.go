package history

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A checkpoint that records an owner puts it back on rollback. Chowning to
// one's own uid and gid is the one ownership change an unprivileged test can
// make, and it still runs the whole restore path.
func TestRollbackRestoresARecordedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(t.TempDir())
	cp := Checkpoint{ID: NewID("fileperms.owner"), FindingID: "fileperms.owner", Label: "owner", CreatedAt: time.Now()}
	saved, err := s.SaveModesAndOwners(cp,
		map[string]os.FileMode{path: 0o600},
		map[string]Owner{path: {UID: os.Getuid(), GID: os.Getgid()}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(saved.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Files[0].Owner == nil || got.Files[0].Owner.UID != os.Getuid() {
		t.Fatalf("the owner did not survive the checkpoint: %+v", got.Files[0])
	}
	if _, err := s.Rollback(saved.ID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	fi, _ := os.Stat(path)
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Getuid() || int(st.Gid) != os.Getgid() {
		t.Errorf("owner after rollback = %d:%d", st.Uid, st.Gid)
	}
}

// A checkpoint written before owners were recorded has none, and a rollback
// must not invent one.
func TestAModeOnlyCheckpointLeavesTheOwnerAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewStore(t.TempDir())
	cp := Checkpoint{ID: NewID("x"), FindingID: "x", Label: "x", CreatedAt: time.Now()}
	saved, err := s.SaveModes(cp, map[string]os.FileMode{path: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(saved.ID)
	if got.Files[0].Owner != nil {
		t.Errorf("SaveModes recorded an owner: %+v", got.Files[0].Owner)
	}
	if _, err := s.Rollback(saved.ID); err != nil {
		t.Fatal(err)
	}
}
