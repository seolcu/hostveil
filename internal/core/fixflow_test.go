package core

import (
	"context"
	"encoding/json"
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

// TestRollbackUnmarksFixedAndRescores guards the long-lived-session case.
// The CLI hides this bug because it builds a fresh engine per invocation,
// but a TUI or web session holds one engine for its lifetime: if Rollback
// restores the files without undoing ApplyFix's mark-fixed→rescore tail,
// the finding stays filtered out of every UI's active list and the gauge
// keeps crediting a fix that no longer exists — a rollback that looks like
// it did nothing.
func TestRollbackUnmarksFixedAndRescores(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}

	f := model.NewFinding("compose.ds018", "exposed datastore", model.SeverityCritical,
		model.SourceCompose, model.RemediationAuto,
		model.WithService("cache"),
		model.WithMetadata("file", path),
		model.WithEvidence("port", "6379"))

	engine := fixEngine(t)
	// Seed the in-memory report the way a real scan would, so mark/unmark
	// and rescore have something to act on.
	engine.current = model.Report{
		Findings: []model.Finding{f},
		Domains:  []model.DomainResult{{Source: model.SourceCompose, State: model.ScanDone, FindingCount: 1}},
	}
	engine.hasRun = true
	before := engine.rescore().Overall

	outcome, err := engine.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !engine.current.Findings[0].Fixed {
		t.Fatal("apply did not mark the finding fixed")
	}
	if outcome.NewScore.Overall <= before {
		t.Fatalf("apply did not improve the score: %d -> %d", before, outcome.NewScore.Overall)
	}

	rb, err := engine.Rollback(outcome.CheckpointID)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if engine.current.Findings[0].Fixed {
		t.Error("rollback left the finding marked fixed — it stays hidden in every UI")
	}
	if len(rb.Unfixed) != 1 || rb.Unfixed[0] != "compose.ds018" {
		t.Errorf("unexpected Unfixed: %v", rb.Unfixed)
	}
	if rb.NewScore.Overall != before {
		t.Errorf("rollback did not restore the score: want %d, got %d", before, rb.NewScore.Overall)
	}
}

// TestRollbackUnmarksOnlyTheCheckpointedService pins the reason checkpoints
// record a full source|id|service key: two services can raise the same
// finding ID, and rolling one back must not resurrect the other.
func TestRollbackUnmarksOnlyTheCheckpointedService(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n" +
		"  queue:\n    image: redis\n    ports:\n      - \"6380:6379\"\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}

	mk := func(service, port string) model.Finding {
		return model.NewFinding("compose.ds018", "exposed datastore", model.SeverityCritical,
			model.SourceCompose, model.RemediationAuto,
			model.WithService(service),
			model.WithMetadata("file", path),
			model.WithEvidence("port", port))
	}
	cache, queue := mk("cache", "6379"), mk("queue", "6380")

	engine := fixEngine(t)
	engine.current = model.Report{
		Findings: []model.Finding{cache, queue},
		Domains:  []model.DomainResult{{Source: model.SourceCompose, State: model.ScanDone, FindingCount: 2}},
	}
	engine.hasRun = true

	cacheOut, err := engine.ApplyFix(context.Background(), cache, 0)
	if err != nil {
		t.Fatalf("apply cache: %v", err)
	}
	if _, err := engine.ApplyFix(context.Background(), queue, 0); err != nil {
		t.Fatalf("apply queue: %v", err)
	}

	if _, err := engine.Rollback(cacheOut.CheckpointID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	for _, f := range engine.current.Findings {
		if f.Service == "cache" && f.Fixed {
			t.Error("cache finding should be un-fixed after rolling its checkpoint back")
		}
		if f.Service == "queue" && !f.Fixed {
			t.Error("queue finding was un-fixed by an unrelated service's rollback")
		}
	}
}

// TestListCheckpointsHidesStorageInternals: the web UI serves this straight
// to the browser, so it must carry paths and a materialized Reversible flag
// and nothing about how backups are stored.
func TestListCheckpointsHidesStorageInternals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  app:\n    image: myapp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding("compose.ds006", "no-new-privileges", model.SeverityMedium,
		model.SourceCompose, model.RemediationAuto,
		model.WithService("app"), model.WithMetadata("file", path))

	engine := fixEngine(t)
	if _, err := engine.ApplyFix(context.Background(), f, 0); err != nil {
		t.Fatalf("apply: %v", err)
	}

	cps, err := engine.ListCheckpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 1 {
		t.Fatalf("want 1 checkpoint, got %d", len(cps))
	}
	cp := cps[0]
	if !cp.Reversible {
		t.Error("an edit fix's checkpoint must be reversible")
	}
	if len(cp.Files) != 1 || cp.Files[0] != path {
		t.Errorf("want the original path, got %v", cp.Files)
	}
	blob, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "blob") {
		t.Errorf("checkpoint JSON leaks backup blob names to the client: %s", blob)
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
// TestApplyBatchOnlyAppliesAuto verifies the batch path applies Auto fixes
// and skips Review/Manual, leaving those for individual handling.
func TestApplyBatchOnlyAppliesAuto(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  app:\n    image: myapp\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := fixEngine(t)

	auto := model.NewFinding("compose.ds006", "nnp", model.SeverityMedium, model.SourceCompose,
		model.RemediationAuto, model.WithService("app"), model.WithMetadata("file", path))
	manual := model.NewFinding("compose.ds001", "priv", model.SeverityHigh, model.SourceCompose,
		model.RemediationManual, model.WithService("app"), model.WithMetadata("file", path))

	out := engine.ApplyBatch(context.Background(), []model.Finding{auto, manual})
	if len(out.Applied) != 1 || out.Applied[0] != "compose.ds006" {
		t.Errorf("applied = %v, want [compose.ds006]", out.Applied)
	}
	if len(out.Skipped) != 1 || out.Skipped[0] != "compose.ds001" {
		t.Errorf("skipped = %v, want [compose.ds001]", out.Skipped)
	}
	applied, _ := os.ReadFile(path)
	if !strings.Contains(string(applied), "no-new-privileges") {
		t.Errorf("auto fix not applied:\n%s", applied)
	}
}

func TestNoFixForUnfixable(t *testing.T) {
	engine := fixEngine(t)
	f := model.NewFinding("compose.ds001", "privileged", model.SeverityHigh,
		model.SourceCompose, model.RemediationManual, model.WithService("app"))
	if _, err := engine.PreviewFix(f); err == nil {
		t.Error("expected error previewing an unfixable finding")
	}
}
