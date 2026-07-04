package history

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

// withTempHistoryDirs points BaseDir/CheckpointDir/ScanDir at a t.TempDir()
// for the duration of the test and restores the originals on cleanup, so
// tests never touch the real /var/lib/hostveil.
func withTempHistoryDirs(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(SetDirsForTest(dir, filepath.Join(dir, "checkpoints"), filepath.Join(dir, "scans")))
}

func TestApplyWithCheckpoint_EditActionCreatesRestorableCheckpoint(t *testing.T) {
	withTempHistoryDirs(t)

	// A real file to edit, standing in for a compose file or sshd_config.
	targetDir := t.TempDir()
	targetPath := filepath.Join(targetDir, "config.yml")
	original := "privileged: true\n"
	if err := os.WriteFile(targetPath, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	f := &fix.Fix{
		FindingID: "test.finding",
		Actions: []fix.Action{{
			Type: fix.ActionEdit,
			Apply: func(ctx fix.Context) error {
				return os.WriteFile(targetPath, []byte("privileged: false\n"), 0644)
			},
		}},
	}
	finding := &domain.Finding{
		ID:       "test.finding",
		Service:  "web",
		Metadata: map[string]string{"compose_path": targetPath},
	}

	result := ApplyWithCheckpoint(f, finding, 0)
	if !result.Success {
		t.Fatalf("ApplyWithCheckpoint failed: %s", result.Error)
	}

	// The edit actually happened.
	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "privileged: false\n" {
		t.Errorf("target file = %q, want the edited content", string(got))
	}

	// A checkpoint was saved and can be rolled back.
	cps, err := ListCheckpoints()
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if len(cps) != 1 {
		t.Fatalf("len(ListCheckpoints()) = %d, want 1", len(cps))
	}
	cp := cps[0]
	if cp.FindingID != "test.finding" || cp.Service != "web" {
		t.Errorf("checkpoint = %+v, want FindingID=test.finding Service=web", cp)
	}
	if len(cp.Backups) != 1 {
		t.Fatalf("len(cp.Backups) = %d, want 1", len(cp.Backups))
	}

	rollback, err := Rollback(cp)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if len(rollback.RestoredFiles) != 1 {
		t.Errorf("len(rollback.RestoredFiles) = %d, want 1", len(rollback.RestoredFiles))
	}
	restored, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Errorf("after rollback, target file = %q, want original %q", string(restored), original)
	}
}

func TestApplyWithCheckpoint_ExecActionDoesNotCreateCheckpoint(t *testing.T) {
	withTempHistoryDirs(t)

	ran := false
	f := &fix.Fix{
		FindingID: "test.exec",
		Actions: []fix.Action{{
			Type: fix.ActionExec,
			Apply: func(ctx fix.Context) error {
				ran = true
				return nil
			},
		}},
	}
	finding := &domain.Finding{ID: "test.exec"}

	result := ApplyWithCheckpoint(f, finding, 0)
	if !result.Success {
		t.Fatalf("ApplyWithCheckpoint failed: %s", result.Error)
	}
	if !ran {
		t.Error("exec action did not run")
	}

	// ActionExec has no file to back up, so no checkpoint should exist.
	cps, err := ListCheckpoints()
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if len(cps) != 0 {
		t.Errorf("len(ListCheckpoints()) = %d, want 0 for an exec-only fix", len(cps))
	}
}

func TestApplyWithCheckpoint_FailedApplyDoesNotSaveCheckpoint(t *testing.T) {
	withTempHistoryDirs(t)

	targetDir := t.TempDir()
	targetPath := filepath.Join(targetDir, "config.yml")
	if err := os.WriteFile(targetPath, []byte("original\n"), 0644); err != nil {
		t.Fatal(err)
	}

	f := &fix.Fix{
		FindingID: "test.fails",
		Actions: []fix.Action{{
			Type: fix.ActionEdit,
			Apply: func(ctx fix.Context) error {
				return os.ErrPermission
			},
		}},
	}
	finding := &domain.Finding{
		ID:       "test.fails",
		Metadata: map[string]string{"compose_path": targetPath},
	}

	result := ApplyWithCheckpoint(f, finding, 0)
	if result.Success {
		t.Fatal("expected failure, got success")
	}

	cps, err := ListCheckpoints()
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if len(cps) != 0 {
		t.Errorf("len(ListCheckpoints()) = %d, want 0 when the fix failed", len(cps))
	}
}

func TestApplyWithCheckpoint_InvalidActionIndex(t *testing.T) {
	withTempHistoryDirs(t)

	f := &fix.Fix{FindingID: "test.oob", Actions: []fix.Action{{Type: fix.ActionEdit, Apply: func(fix.Context) error { return nil }}}}
	finding := &domain.Finding{ID: "test.oob"}

	result := ApplyWithCheckpoint(f, finding, 5)
	if result.Success {
		t.Error("expected failure for out-of-range action index")
	}
	if result.Error == "" {
		t.Error("expected an error message for out-of-range action index")
	}
}
