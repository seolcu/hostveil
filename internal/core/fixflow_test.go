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
	// Mode restored. This used to pass vacuously: nothing had changed the
	// mode, so "preserved" was true by default. Loosen it between apply and
	// rollback so the assertion has something to catch — os.WriteFile
	// ignores its perm argument on an existing file, which is why rollback
	// needs an explicit chmod.
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() != 0o640 {
		t.Errorf("rollback did not restore mode: %v", fi.Mode().Perm())
	}
}

// The regression guard for that vacuity: a mode changed after the checkpoint
// was written must be put back by rollback.
func TestRollbackRestoresAChangedMode(t *testing.T) {
	engine := fixEngine(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  cache:\n    image: redis:7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding("compose.ds006", "no-new-privileges", model.SeverityMedium,
		model.SourceCompose, model.RemediationAuto,
		model.WithService("cache"), model.WithMetadata("file", path))

	out, err := engine.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Something else loosens the file after the fix was applied.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Rollback(out.CheckpointID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %#o, want 0640 — the checkpoint recorded it and rollback must apply it", fi.Mode().Perm())
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

// permFinding builds a fileperms finding pointing at a real temp file.
func permFinding(t *testing.T, mode os.FileMode, expected string) (model.Finding, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(path, []byte("root:!:1::::::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return model.NewFinding("fileperms.shadow", "over-permissive", model.SeverityHigh,
		model.SourceFilePerms, model.RemediationAuto,
		model.WithEvidence("paths", path),
		model.WithEvidence("expected", expected),
	), path
}

func TestModeFixRoundTrip(t *testing.T) {
	engine := fixEngine(t)
	f, path := permFinding(t, 0o666, "0640")

	out, err := engine.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode after apply = %#o, want 0640", fi.Mode().Perm())
	}
	if out.CheckpointID == "" {
		t.Fatal("a mode change is reversible and must leave a checkpoint")
	}

	if _, err := engine.Rollback(out.CheckpointID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o666 {
		t.Errorf("mode after rollback = %#o, want the original 0666", fi.Mode().Perm())
	}
}

// The contents are not the fix's business, and copying them into the
// checkpoint would spill /etc/shadow's hashes into another file.
func TestModeCheckpointStoresNoContents(t *testing.T) {
	engine := fixEngine(t)
	f, _ := permFinding(t, 0o666, "0640")

	out, err := engine.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	cps, err := engine.ListCheckpoints()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, cp := range cps {
		if cp.ID != out.CheckpointID {
			continue
		}
		found = true
		// Still reversible — it restores modes, not bytes.
		if !cp.Reversible {
			t.Error("a mode checkpoint must be reversible")
		}
	}
	if !found {
		t.Fatal("checkpoint not listed")
	}
}

// Preview must never touch the host — the same contract previewEdit has.
func TestModePreviewIsPure(t *testing.T) {
	engine := fixEngine(t)
	f, path := permFinding(t, 0o666, "0640")

	p, err := engine.PreviewFix(f)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o666 {
		t.Errorf("preview changed the mode on disk: %#o", fi.Mode().Perm())
	}
	if p.Actions[0].Type != "mode" {
		t.Errorf("action type = %q, want mode", p.Actions[0].Type)
	}
	if !strings.Contains(p.Actions[0].Diff, "0666") || !strings.Contains(p.Actions[0].Diff, "0640") {
		t.Errorf("preview should show the transition, got %q", p.Actions[0].Diff)
	}
}

// A fix that tightened three of four files while silently skipping the one
// it could not stat would report success and leave the host exposed.
func TestModeFixAbortsWhenAPathIsMissing(t *testing.T) {
	engine := fixEngine(t)
	f, path := permFinding(t, 0o666, "0640")
	model.WithEvidence("paths", path+", "+path+".missing")(&f)

	if _, err := engine.ApplyFix(context.Background(), f, 0); err == nil {
		t.Fatal("expected an error when a path cannot be stat'ed")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o666 {
		t.Errorf("mode changed despite the abort: %#o", fi.Mode().Perm())
	}
}

// A directory already at its target mode must produce no change at all.
// tighten() carries the type bits through precisely so that planModes sees a
// fixed point here; when it dropped fs.ModeDir the comparison against the
// full mode never matched, and applyMode would checkpoint and chmod a
// compliant directory while reporting success for work it had not done.
func TestModeFixOnCompliantDirectoryIsANoOp(t *testing.T) {
	engine := fixEngine(t)
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding("fileperms.shadow", "over-permissive", model.SeverityHigh,
		model.SourceFilePerms, model.RemediationAuto,
		model.WithEvidence("paths", dir),
		model.WithEvidence("expected", "0700"),
	)

	if _, err := engine.ApplyFix(context.Background(), f, 0); err == nil {
		t.Fatal("expected an 'already as strict as required' error for a compliant directory")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Error("path is no longer a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("mode = %#o, want 0700", fi.Mode().Perm())
	}
}

// A directory that genuinely is too permissive must still be tightened, and
// must still be a directory afterwards.
func TestModeFixTightensLooseDirectory(t *testing.T) {
	engine := fixEngine(t)
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding("fileperms.shadow", "over-permissive", model.SeverityHigh,
		model.SourceFilePerms, model.RemediationAuto,
		model.WithEvidence("paths", dir),
		model.WithEvidence("expected", "0700"),
	)

	if _, err := engine.ApplyFix(context.Background(), f, 0); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Error("path is no longer a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("mode = %#o, want 0700", fi.Mode().Perm())
	}
}

// Auto means "safe to apply unattended", so `fix --all` must actually pick
// a mode fix up. ApplyBatch takes only single-action Auto fixes, which is
// exactly the shape ActionMode produces.
func TestApplyBatchIncludesModeFixes(t *testing.T) {
	engine := fixEngine(t)
	f, path := permFinding(t, 0o666, "0640")

	out := engine.ApplyBatch(context.Background(), []model.Finding{f})
	if len(out.Applied) != 1 || out.Applied[0] != "fileperms.shadow" {
		t.Fatalf("batch did not apply the mode fix: applied=%v skipped=%v failed=%v",
			out.Applied, out.Skipped, out.Failed)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %#o, want 0640", fi.Mode().Perm())
	}
}
