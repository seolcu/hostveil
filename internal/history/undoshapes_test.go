package history

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Save has two siblings and neither had a test.
//
// A checkpoint describes what undoing a fix means, and for most fixes that is
// "write these bytes back". Two shapes cannot be said that way. SaveModes is
// for a fix that changed a file's permissions and not its contents, so there
// is nothing to write. SaveCreations is for a fix that wrote a file which did
// not exist — a sysctl drop-in, an apt auto-upgrades file — where undoing it
// means **deleting** the file.
//
// That second one is the most dangerous operation in this package. Everywhere
// else a rollback that goes wrong writes the wrong bytes; here it removes a
// file, and rollback keeps no backup of its own. Both were at 0% coverage.

func creationStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	return NewStore(dir), dir
}

func newCheckpoint(id, path, appliedSum string) Checkpoint {
	cp := Checkpoint{
		ID:        id,
		FindingID: "sysctl.example",
		Label:     "write a drop-in",
		CreatedAt: time.Now(),
	}
	if appliedSum != "" {
		cp.AppliedSHA256 = map[string]string{path: appliedSum}
	}
	return cp
}

func TestSaveCreationsRecordsAnAbsenceRatherThanAnEmptyBackup(t *testing.T) {
	s, _ := creationStore(t)
	target := filepath.Join(t.TempDir(), "60-hostveil.conf")
	content := []byte("net.ipv4.conf.all.rp_filter = 1\n")
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatal(err)
	}

	cp, err := s.SaveCreations(newCheckpoint(NewID("sysctl.example"), target, SHA256Hex(content)), []string{target})
	if err != nil {
		t.Fatal(err)
	}
	if !cp.Reversible() {
		t.Error("a creation checkpoint is not reversible, so the fix reads as unrecoverable " +
			"when deleting one file is all it takes")
	}
	if len(cp.Files) != 1 {
		t.Fatalf("checkpoint records %d files, want 1", len(cp.Files))
	}
	f := cp.Files[0]
	if !f.Created {
		t.Error("the entry is not marked Created, so rollback would try to write bytes back " +
			"and restoring an empty file is not restoring an absence")
	}
	if f.Blob != "" {
		t.Errorf("a creation checkpoint stored a blob (%q); there was nothing to back up", f.Blob)
	}
}

func TestRollingBackACreationDeletesTheFile(t *testing.T) {
	s, _ := creationStore(t)
	target := filepath.Join(t.TempDir(), "20auto-upgrades")
	content := []byte(`APT::Periodic::Unattended-Upgrade "1";` + "\n")
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatal(err)
	}
	cp, err := s.SaveCreations(newCheckpoint(NewID("updates.disabled"), target, SHA256Hex(content)), []string{target})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(cp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("the created file is still there after rollback (stat err: %v)", err)
	}
}

// An operator who deleted the drop-in by hand and then rolled back should get
// success, not a failure describing the thing they already did.
func TestRollingBackACreationThatIsAlreadyGoneSucceeds(t *testing.T) {
	s, _ := creationStore(t)
	target := filepath.Join(t.TempDir(), "gone.conf")
	if err := os.WriteFile(target, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cp, err := s.SaveCreations(newCheckpoint(NewID("sysctl.example"), target, SHA256Hex([]byte("x\n"))), []string{target})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(cp.ID); err != nil {
		t.Errorf("rollback of an already-absent creation failed: %v", err)
	}
}

// The one that matters. rollback()'s comment says a created file the operator
// has since edited "declines here rather than being deleted out from under
// them", and that rests on apply.go recording AppliedSHA256 *before* calling
// SaveCreations and on SaveCreations preserving it. Both are true and neither
// was checked, on the single code path in this repository whose undo is a
// delete and whose mistake cannot be undone.
func TestRollingBackACreationDeclinesWhenTheOperatorHasEditedIt(t *testing.T) {
	s, _ := creationStore(t)
	target := filepath.Join(t.TempDir(), "60-hostveil.conf")
	written := []byte("net.ipv4.conf.all.rp_filter = 1\n")
	if err := os.WriteFile(target, written, 0o644); err != nil {
		t.Fatal(err)
	}
	cp, err := s.SaveCreations(newCheckpoint(NewID("sysctl.example"), target, SHA256Hex(written)), []string{target})
	if err != nil {
		t.Fatal(err)
	}

	edited := append(written, []byte("kernel.dmesg_restrict = 1  # mine\n")...)
	if err := os.WriteFile(target, edited, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = s.Rollback(cp.ID)
	if err == nil {
		t.Fatal("rollback deleted a file the operator had edited since the fix ran")
	}
	var ee *ExternalEditError
	if !errors.As(err, &ee) {
		t.Errorf("rollback failed with %v, want an ExternalEditError so a UI can tell a "+
			"declined rollback from a broken one", err)
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("the file is gone after a refusal: %v", readErr)
	}
	if string(got) != string(edited) {
		t.Error("the operator's edit did not survive the refusal")
	}

	// --force is the escape hatch, and it must actually delete.
	if _, err := s.RollbackForce(cp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("RollbackForce left the created file in place")
	}
}

func TestSaveModesRestoresThePriorModeAndTouchesNoBytes(t *testing.T) {
	s, _ := creationStore(t)
	target := filepath.Join(t.TempDir(), "shadow")
	content := []byte("root:!:20000:0:99999:7:::\n")
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatal(err)
	}

	cp, err := s.SaveModes(Checkpoint{
		ID:        NewID("fileperms.shadow"),
		FindingID: "fileperms.shadow",
		Label:     "tighten /etc/shadow",
		CreatedAt: time.Now(),
	}, map[string]os.FileMode{target: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	if !cp.Reversible() {
		t.Error("a mode checkpoint is not reversible, so tightening permissions would read " +
			"as something that cannot be undone")
	}
	if len(cp.Files) != 1 || cp.Files[0].Blob != "" {
		t.Fatalf("mode checkpoint files = %+v; it must name the path and store no blob", cp.Files)
	}
	if cp.Files[0].Mode != 0o644 {
		t.Errorf("recorded mode is %v, want the mode the file had before the fix", cp.Files[0].Mode)
	}

	// The fix tightens it; rollback must put it back, and must not rewrite
	// the contents on the way — a mode fix never had a copy of them.
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(cp.ID); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode after rollback is %v, want 0644", fi.Mode().Perm())
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Error("rolling back a mode change rewrote the file's contents")
	}
}

// Every shape has to survive the round trip through disk, because that is how
// a rollback in a later process reads it. A Created flag or a Mode that did
// not marshal would turn a delete into a write, or a chmod into nothing.
func TestUndoShapesSurviveTheMetadataRoundTrip(t *testing.T) {
	s, dir := creationStore(t)
	created := filepath.Join(t.TempDir(), "created.conf")
	moded := filepath.Join(t.TempDir(), "moded.conf")
	for _, p := range []string{created, moded} {
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SaveCreations(newCheckpoint(NewID("a.created"), created, SHA256Hex([]byte("x\n"))), []string{created}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveModes(Checkpoint{ID: NewID("a.moded"), FindingID: "a.moded", CreatedAt: time.Now()},
		map[string]os.FileMode{moded: 0o640}); err != nil {
		t.Fatal(err)
	}

	// A fresh Store, so nothing is served from memory.
	list, err := NewStore(dir).List()
	if err != nil {
		t.Fatal(err)
	}
	var sawCreated, sawMode bool
	for _, cp := range list {
		for _, f := range cp.Files {
			switch f.Path {
			case created:
				sawCreated = f.Created
				if f.Blob != "" {
					t.Error("a creation entry came back with a blob")
				}
			case moded:
				sawMode = f.Mode == 0o640
			}
		}
	}
	if !sawCreated {
		t.Error("the Created flag did not survive being written and read back, so a later " +
			"rollback would try to write bytes back instead of deleting the file")
	}
	if !sawMode {
		t.Error("the recorded mode did not survive the round trip")
	}
}
