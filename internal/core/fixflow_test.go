package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

func fixEngine(t *testing.T) *Engine {
	t.Helper()
	return New(Config{
		Fixes: fix.Default(),
		Store: history.NewStore(t.TempDir()),
	})
}

// TestPreviewIsPure is the regression guard against v2's SimulateDiff
// hazard: computing a preview must never alter the target file.
func TestPreviewIsPure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  app:\n    image: myapp\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}

	f := model.NewFinding("compose.ds006", "no-new-privileges", model.SeverityMedium,
		model.SourceCompose, model.RemediationAuto,
		model.WithService("app"), model.WithMetadata("file", path))

	preview, err := fixEngine(t).PreviewFix(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Actions) == 0 || preview.Actions[0].Diff == "" {
		t.Fatal("preview produced no diff")
	}

	after, _ := os.ReadFile(path)
	if string(after) != orig {
		t.Errorf("PreviewFix mutated the live file!\nwant:\n%s\ngot:\n%s", orig, after)
	}
}

// TestApplyRollbackRoundTrip verifies the differentiator end to end: apply
// changes the file, rollback restores it byte-for-byte.
func TestApplyRollbackRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"
	if err := os.WriteFile(path, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}

	engine := fixEngine(t)
	f := model.NewFinding("compose.ds018", "exposed datastore", model.SeverityCritical,
		model.SourceCompose, model.RemediationAuto,
		model.WithService("cache"),
		model.WithMetadata("file", path),
		model.WithEvidence("port", "6379"))

	outcome, err := engine.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !outcome.Success || outcome.CheckpointID == "" {
		t.Fatalf("apply outcome: %+v", outcome)
	}

	applied, _ := os.ReadFile(path)
	if !strings.Contains(string(applied), "127.0.0.1:6379:6379") {
		t.Errorf("fix not applied to file:\n%s", applied)
	}
	if string(applied) == orig {
		t.Error("file unchanged after apply")
	}

	// Rollback restores the exact original bytes.
	rb, err := engine.Rollback(outcome.CheckpointID)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if len(rb.RestoredFiles) != 1 || rb.RestoredFiles[0] != path {
		t.Errorf("unexpected restored files: %v", rb.RestoredFiles)
	}

	restored, _ := os.ReadFile(path)
	if string(restored) != orig {
		t.Errorf("rollback did not restore original bytes:\nwant:\n%s\ngot:\n%s", orig, restored)
	}
	// Mode preserved.
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() != 0o640 {
		t.Errorf("rollback did not preserve mode: %v", fi.Mode().Perm())
	}
}

// TestSSHFixRoundTrip covers a non-compose (line-based) edit fix.
func TestSSHFixRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	orig := "PermitEmptyPasswords yes\nPort 22\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}

	engine := fixEngine(t)
	f := model.NewFinding("ssh.emptypasswords", "empty passwords", model.SeverityCritical,
		model.SourceSSH, model.RemediationAuto,
		model.WithEvidence("config", path))

	out, err := engine.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatal(err)
	}
	applied, _ := os.ReadFile(path)
	if !strings.Contains(string(applied), "PermitEmptyPasswords no") {
		t.Errorf("ssh fix not applied:\n%s", applied)
	}

	if _, err := engine.Rollback(out.CheckpointID); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(path)
	if string(restored) != orig {
		t.Errorf("ssh rollback mismatch:\nwant %q\ngot %q", orig, restored)
	}
}

// TestApplyBacksUpBeforeWriting ensures a failed write still leaves a
// recoverable checkpoint (backup happens before the write).
func TestNoFixForUnfixable(t *testing.T) {
	engine := fixEngine(t)
	f := model.NewFinding("compose.ds001", "privileged", model.SeverityHigh,
		model.SourceCompose, model.RemediationManual, model.WithService("app"))
	if _, err := engine.PreviewFix(f); err == nil {
		t.Error("expected error previewing an unfixable finding")
	}
}
