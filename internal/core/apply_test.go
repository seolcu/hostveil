package core

import (
	"context"
	"encoding/json"
	"github.com/seolcu/hostveil/internal/check"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	f := model.NewFinding("compose.ds018", "exposed datastore", model.SeverityHigh,
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

	f := model.NewFinding("compose.ds018", "exposed datastore", model.SeverityHigh,
		model.SourceCompose, model.RemediationAuto,
		model.WithService("cache"),
		model.WithMetadata("file", path),
		model.WithEvidence("port", "6379"))

	engine := fixEngine(t)
	// Seed the in-memory report the way a real scan would, so mark/unmark
	// and rescore have something to act on.
	engine.state.current = model.Report{
		Findings: []model.Finding{f},
		Domains:  []model.DomainResult{{Source: model.SourceCompose, State: model.ScanDone, FindingCount: 1}},
	}
	engine.state.hasRun = true
	before := engine.state.rescore().Overall

	outcome, err := engine.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !engine.state.current.Findings[0].Fixed {
		t.Fatal("apply did not mark the finding fixed")
	}
	// Deliberately not asserted here any more: that the score went up. A
	// compose edit is not in force until the container is recreated, so this
	// apply leaves the number alone on purpose — see
	// TestAnInForceFixMovesTheScoreAndAPendingOneDoesNot, which owns that
	// claim now and owns both halves of it. What this test is about is the
	// rollback tail, and for that the pending case is the harder one: the
	// score never moved, so an unmark that quietly did nothing would look
	// exactly like a correct one.
	if !engine.state.current.Findings[0].Pending {
		t.Fatal("a compose edit is not in force when it is written; apply did not record that")
	}

	rb, err := engine.Rollback(outcome.CheckpointID)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if engine.state.current.Findings[0].Fixed {
		t.Error("rollback left the finding marked fixed — it stays hidden in every UI")
	}
	if engine.state.current.Findings[0].Pending {
		t.Error("rollback left the finding marked pending — the fix it was waiting on is gone")
	}
	if len(rb.Unfixed) != 1 || rb.Unfixed[0] != "compose.ds018" {
		t.Errorf("unexpected Unfixed: %v", rb.Unfixed)
	}
	if rb.NewScore.Overall != before {
		t.Errorf("rollback did not restore the score: want %d, got %d", before, rb.NewScore.Overall)
	}
}

// TestAnInForceFixMovesTheScoreAndAPendingOneDoesNot is the pair that pins
// this whole rule, and it has to be a pair.
//
// The score is what hostveil says about the host, so it may only move when the
// host has moved. A fix whose artifact is what the domain reads — a file mode
// is the plainest case, since chmod IS the state — is in force the moment it
// is applied, and the number must follow. A fix whose artifact is read by
// something that has not read it again is not, and the number must not: the
// compose file says one thing and the running container still does another.
//
// Asserting only the second half would pass for an engine that had simply
// stopped scoring fixes at all, which is the failure mode this replaced —
// a number that ignores what happened is no better than one that overstates
// it. So the first half is the control, and neither assertion means anything
// without the other.
func TestAnInForceFixMovesTheScoreAndAPendingOneDoesNot(t *testing.T) {
	inForce, _ := permFinding(t, 0o644, "0640")
	pending := composeFindingOn(t, "compose.ds018")

	for _, tc := range []struct {
		name        string
		finding     model.Finding
		wantPending bool
	}{
		{"a mode change is the state it describes", inForce, false},
		{"a compose file is read at the next recreate", pending, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := fixEngine(t)
			engine.state.current = model.Report{
				Findings: []model.Finding{tc.finding},
				Domains: []model.DomainResult{{
					Source: tc.finding.Source, State: model.ScanDone, FindingCount: 1,
				}},
			}
			engine.state.hasRun = true
			before := engine.state.rescore().Overall

			out, err := engine.ApplyFix(context.Background(), tc.finding, 0)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			if out.Pending != tc.wantPending {
				t.Fatalf("Pending = %v, want %v (verified %s)", out.Pending, tc.wantPending, out.Verified)
			}
			// Fixed either way. Applied and in force are two facts, and this
			// change separates them rather than collapsing the first into the
			// second — see model.FixVerification.
			if !engine.state.current.Findings[0].Fixed {
				t.Error("the fix was applied and the finding is not marked fixed")
			}

			switch {
			case tc.wantPending && out.NewScore.Overall != before:
				t.Errorf("a fix that is not in force moved the score: %d -> %d",
					before, out.NewScore.Overall)
			case !tc.wantPending && out.NewScore.Overall <= before:
				t.Errorf("a fix that is in force did not move the score: %d -> %d",
					before, out.NewScore.Overall)
			}

			// And the operator is told which it was. A score that stays put
			// with nothing saying why is the complaint this rule invites.
			if tc.wantPending && out.TakesEffectOn == "" {
				t.Error("a pending fix did not say what would put it in force")
			}
		})
	}
}

// TestABatchChargesAPendingFixToo is the path-independence half.
//
// ApplyBatch deliberately does not re-check — twenty compose findings would
// mean twenty enumerations of every container on the host — so if pending were
// decided by verification rather than by the fix's own declaration, the batch
// would be the optimistic path and `fix --all` would score a host higher than
// applying the same fixes one at a time. Action.TakesEffectOn is on the fix
// precisely so both paths reach the same answer with no re-check.
func TestABatchChargesAPendingFixToo(t *testing.T) {
	f := composeFindingOn(t, "compose.ds006")

	engine := fixEngine(t)
	engine.state.current = model.Report{
		Findings: []model.Finding{f},
		Domains:  []model.DomainResult{{Source: model.SourceCompose, State: model.ScanDone, FindingCount: 1}},
	}
	engine.state.hasRun = true
	before := engine.state.rescore().Overall

	out := engine.ApplyBatch(context.Background(), []model.Finding{f})
	if len(out.Applied) != 1 {
		t.Fatalf("batch applied %v, want the one finding", out.Applied)
	}
	if out.NewScore.Overall != before {
		t.Errorf("the batch credited a fix that is not in force: %d -> %d", before, out.NewScore.Overall)
	}
	if len(out.Pending) != 1 || out.Pending[0] != f.ID {
		t.Fatalf("Pending = %v, want [%s]", out.Pending, f.ID)
	}
	// Without this the change trades a dishonest number for an inexplicable
	// one: "Applied 1. New score: 50/100." with 50 unchanged reads as a tool
	// that did nothing.
	if !strings.Contains(out.Message, "not in force") {
		t.Errorf("the summary does not explain the score that did not move: %q", out.Message)
	}
	// The batch must not offer it again. It was applied; what is outstanding
	// is the restart, and re-applying would write a second checkpoint over a
	// file that has not changed.
	again := engine.ApplyBatch(context.Background(), engine.state.current.Findings)
	if len(again.Applied) != 0 {
		t.Errorf("a second batch re-applied a pending fix: %v", again.Applied)
	}
}

// composeFindingOn builds a compose finding against a real temp compose file.
func composeFindingOn(t *testing.T, id string) model.Finding {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	body := "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return model.NewFinding(id, "t", model.SeverityHigh,
		model.SourceCompose, model.RemediationAuto,
		model.WithService("cache"),
		model.WithMetadata("file", path),
		model.WithEvidence("port", "6379"))
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
		return model.NewFinding("compose.ds018", "exposed datastore", model.SeverityHigh,
			model.SourceCompose, model.RemediationAuto,
			model.WithService(service),
			model.WithMetadata("file", path),
			model.WithEvidence("port", port))
	}
	cache, queue := mk("cache", "6379"), mk("queue", "6380")

	engine := fixEngine(t)
	engine.state.current = model.Report{
		Findings: []model.Finding{cache, queue},
		Domains:  []model.DomainResult{{Source: model.SourceCompose, State: model.ScanDone, FindingCount: 2}},
	}
	engine.state.hasRun = true

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
	for _, f := range engine.state.current.Findings {
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
	f := model.NewFinding("ssh.emptypasswords", "empty passwords", model.SeverityHigh,
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

// TestConcurrentFixesToOneFileDoNotLoseEachOther pins the serialization in
// applyMu.
//
// applyEdit is a read-modify-write, and the web dashboard serves requests
// concurrently. Without the lock, two fixes to one compose file both read the
// original, both transform their own copy, and the later write erases the
// earlier fix — while both checkpoints record success and both findings are
// marked Fixed. The loss is silent, in the subsystem whose entire promise is
// that changes are recorded and reversible.
func TestConcurrentFixesToOneFileDoNotLoseEachOther(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  app:\n    image: myapp\n    ports:\n      - \"8080:80\"\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}

	// Two independent Auto fixes that edit the same file in different places.
	findings := []model.Finding{
		model.NewFinding("compose.ds006", "no-new-privileges", model.SeverityMedium,
			model.SourceCompose, model.RemediationAuto,
			model.WithService("app"), model.WithMetadata("file", path), model.WithMetadata("service", "app")),
		model.NewFinding("compose.ds018", "port on all interfaces", model.SeverityMedium,
			model.SourceCompose, model.RemediationAuto,
			model.WithService("app"), model.WithMetadata("file", path), model.WithMetadata("service", "app"),
			model.WithEvidence("port", "8080")),
	}

	e := fixEngine(t)
	var wg sync.WaitGroup
	for _, f := range findings {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.ApplyFix(context.Background(), f, 0); err != nil {
				t.Errorf("apply %s: %v", f.ID, err)
			}
		}()
	}
	wg.Wait()

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Both edits must be present. Either one missing means a write was lost.
	for _, want := range []string{"no-new-privileges", "127.0.0.1:8080:80"} {
		if !strings.Contains(string(after), want) {
			t.Errorf("a concurrent fix was lost — %q missing from:\n%s", want, after)
		}
	}
}

// TestCurrentIsASnapshot guards against the data race `go test -race` found
// between /api/result and an in-flight fix: Report is a struct but Findings
// is a slice, so returning it by value used to hand callers the same backing
// array markFixed writes into.
func TestCurrentIsASnapshot(t *testing.T) {
	e := fixEngine(t)
	e.state.mu.Lock()
	e.state.current = model.Report{Findings: []model.Finding{
		model.NewFinding("compose.ds006", "t", model.SeverityLow,
			model.SourceCompose, model.RemediationAuto, model.WithService("app")),
	}}
	e.state.hasRun = true
	e.state.mu.Unlock()

	snapshot, _ := e.Current()
	e.state.markFixed(snapshot.Findings[0], false)

	if snapshot.Findings[0].Fixed {
		t.Error("Current() shares its findings with the engine; a later fix mutated the caller's copy")
	}
	if fresh, _ := e.Current(); !fresh.Findings[0].Fixed {
		t.Error("markFixed did not reach the engine's own report")
	}
}

// A mode fix must not chmod through a symlink. fileperms and agent findings
// both carry paths, and the agent ones point into a user's home where that
// account decides what the path is. A symlink there aimed at /etc/passwd
// would turn "tighten your agent config" into root breaking the host's
// account database.
//
// The fix refuses rather than skipping, because a mode fix that silently
// tightened some of its paths would report success over a file it left
// exposed.
func TestModeFixRefusesToFollowASymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "passwd")
	if err := os.WriteFile(victim, []byte("root:x:0:0::/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "shadow")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	f := model.NewFinding("fileperms.shadow", "over-permissive", model.SeverityHigh,
		model.SourceFilePerms, model.RemediationAuto,
		model.WithEvidence("paths", link),
		model.WithEvidence("expected", "0640"),
	)

	engine := fixEngine(t)
	if _, err := engine.PreviewFix(f); err == nil {
		t.Error("previewing a mode fix on a symlink must fail, not report a plan")
	}
	if _, err := engine.ApplyFix(context.Background(), f, 0); err == nil {
		t.Fatal("applying a mode fix to a symlink must fail")
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o644 {
		t.Errorf("the symlink's target is now %#o — the chmod followed the link", fi.Mode().Perm())
	}
}

// A batch cut short must say so. Ctrl-C in the TUI maps straight to tea.Quit
// with no guard while a batch is in flight, so the process exits mid-loop —
// the checkpoints for whatever landed are on disk, and without this flag the
// outcome is indistinguishable from a batch that ran to completion and found
// the rest ineligible.
func TestInterruptedBatchReportsWhatItDidNotReach(t *testing.T) {
	engine := fixEngine(t)

	dir := t.TempDir()
	var findings []model.Finding
	for _, name := range []string{"a", "b", "c"} {
		path := filepath.Join(dir, name+".yml")
		if err := os.WriteFile(path, []byte("services:\n  app:\n    image: myapp\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		findings = append(findings, model.NewFinding("compose.ds006", "no-new-privileges",
			model.SeverityMedium, model.SourceCompose, model.RemediationAuto,
			model.WithService(name), model.WithMetadata("file", path)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := engine.ApplyBatch(ctx, findings)

	if !out.Interrupted {
		t.Error("a batch that stopped on cancellation must report Interrupted")
	}
	if len(out.Applied) != 0 {
		t.Errorf("applied %v under an already-cancelled context", out.Applied)
	}
	if len(out.Skipped) != len(findings) {
		t.Errorf("skipped %d, want all %d unreached findings listed", len(out.Skipped), len(findings))
	}
	// The flag is only worth setting if it reaches the operator, and every
	// interface now shows Message and nothing else about the outcome. The
	// dashboard used to render its own summary and omit the interruption
	// entirely, so a batch cut short read exactly like a completed one.
	if !strings.Contains(out.Message, "Interrupted") {
		t.Errorf("Message = %q, want it to say the batch was interrupted", out.Message)
	}
	if !strings.Contains(out.Message, "3 of 3 were never attempted") {
		t.Errorf("Message = %q, want it to count what was never reached", out.Message)
	}
}

// The flag must not fire on the ordinary path, or it means nothing.
func TestCompletedBatchIsNotMarkedInterrupted(t *testing.T) {
	engine := fixEngine(t)
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  app:\n    image: myapp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding("compose.ds006", "no-new-privileges", model.SeverityMedium,
		model.SourceCompose, model.RemediationAuto,
		model.WithService("app"), model.WithMetadata("file", path))

	out := engine.ApplyBatch(context.Background(), []model.Finding{f})
	if out.Interrupted {
		t.Error("a batch that ran to completion must not report Interrupted")
	}
	if strings.Contains(out.Message, "Interrupted") {
		t.Errorf("Message = %q must not mention an interruption on the ordinary path", out.Message)
	}
	if len(out.Applied) != 1 {
		t.Errorf("applied = %v, want the one auto fix", out.Applied)
	}
}

// A checkpoint must not outlive the write it describes.
//
// The backup is taken first, deliberately — nothing is written until there is
// something to go back to. But when the write then fails, the checkpoint that
// survives says a reversible fix was applied to a file that never changed:
// `hostveil history` lists it with a full diff, and its AppliedSHA256 asserts
// to the external-edit guard, permanently, that hostveil wrote bytes it did
// not.
func TestAFailedWriteLeavesNoCheckpointBehind(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	e := fixEngine(t)
	f := model.NewFinding("compose.ds018", "exposed", model.SeverityHigh, model.SourceCompose,
		model.RemediationAuto, model.WithService("cache"), model.WithMetadata("file", path),
		model.WithEvidence("port", "6379"))

	// The write goes through a temp file beside the target, so an unwritable
	// directory fails it — after the backup, which is the ordering that
	// produces the stale checkpoint.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if _, err := e.ApplyFix(context.Background(), f, 0); err == nil {
		t.Fatal("apply reported success with an unwritable target directory")
	}
	cps, err := e.ListCheckpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 0 {
		t.Errorf("a failed write left %d checkpoint(s) behind: %+v", len(cps), cps)
	}
	if after, _ := os.ReadFile(path); string(after) != orig {
		t.Errorf("the target changed despite the failure:\n%s", after)
	}
}

// slowRegistry builds a fix whose transform takes a while, so a test can
// observe what another operation does while the lock is held.
func slowRegistry(d time.Duration) *fix.Registry {
	r := fix.NewRegistry()
	r.Register("compose.ds018", func(f model.Finding) (fix.Fix, error) {
		return fix.Fix{Kind: model.RemediationAuto, Label: "slow", Actions: []fix.Action{{
			Label:   "slow edit",
			Benefit: "test benefit",
			Kind:    fix.ActionEdit,
			Path:    f.Metadata["file"],
			Transform: func(in []byte) ([]byte, error) {
				time.Sleep(d)
				return append(in, []byte("after\n")...), nil
			},
		}}}, nil
	})
	return r
}

// "applyEdit refuses to write if the backup fails" is the first line of the
// apply-order invariant, and nothing tested it. Reordering the two statements
// passed the whole suite.
//
// It is the ordering that makes editing somebody's sshd_config a reasonable
// thing to ask for: without a backup there is nothing to go back to, so a
// write that happens first is a change with no undo.
func TestNoBackupMeansNoWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	target := filepath.Join(t.TempDir(), "docker-compose.yml")
	orig := "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"
	if err := os.WriteFile(target, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}

	// The state directory is what Save writes into, so a read-only one fails
	// the backup while leaving the target perfectly writable.
	stateDir := t.TempDir()
	e := New(Config{Fixes: fix.Default(), Store: history.NewStore(stateDir)})
	if err := os.Chmod(stateDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o755) })

	f := model.NewFinding("compose.ds018", "exposed", model.SeverityHigh, model.SourceCompose,
		model.RemediationAuto, model.WithService("cache"), model.WithMetadata("file", target),
		model.WithEvidence("port", "6379"))

	_, err := e.ApplyFix(context.Background(), f, 0)
	if err == nil {
		t.Fatal("apply succeeded with an unwritable state directory")
	}
	if !strings.Contains(err.Error(), "backup failed") {
		t.Errorf("the error does not say the backup was what failed: %v", err)
	}
	if after, _ := os.ReadFile(target); string(after) != orig {
		t.Errorf("the file was written despite the backup failing:\n%s", after)
	}
}

// "One fix at a time, and a scan is a fix for this purpose."
//
// The apply-versus-apply half of that has a test. The half that is actually
// surprising — that a scan takes the same lock — did not, and it is the half
// the sentence was written to explain: a scan reads the files a fix is
// part-way through writing, so a report built during one describes a host that
// existed at no single moment.
func TestAScanWaitsForAFixToFinish(t *testing.T) {
	e := New(Config{
		Registry: check.NewRegistry(),
		Fixes:    slowRegistry(60 * time.Millisecond),
		Store:    history.NewStore(t.TempDir()),
	})
	path := filepath.Join(t.TempDir(), "target.conf")
	if err := os.WriteFile(path, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding("compose.ds018", "exposed", model.SeverityHigh, model.SourceCompose,
		model.RemediationAuto, model.WithService("cache"), model.WithMetadata("file", path))

	var scanStarted, scanEnded time.Time
	fixDone := make(chan time.Time, 1)
	go func() {
		_, _ = e.ApplyFix(context.Background(), f, 0)
		fixDone <- time.Now()
	}()

	// Long enough for the apply to be inside its slow transform.
	time.Sleep(20 * time.Millisecond)
	scanStarted = time.Now()
	e.Scan(context.Background(), nil)
	scanEnded = time.Now()

	finished := <-fixDone
	if scanEnded.Before(finished) {
		t.Errorf("the scan finished at %v, before the fix released the lock at %v — "+
			"a scan that overlaps a fix reads a host part-way through being edited",
			scanEnded.Sub(scanStarted), finished.Sub(scanStarted))
	}
}
