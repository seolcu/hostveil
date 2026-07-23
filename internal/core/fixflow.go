package core

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/diff"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// PreviewFix returns, per available action, exactly what the fix would
// change — a unified diff for edits, the command list for execs — WITHOUT
// touching any file or running anything. This is the single preview path
// all UIs use.
func (e *Engine) PreviewFix(f model.Finding) (model.FixPreview, error) {
	fx, ok, err := e.buildFix(f)
	if err != nil {
		return model.FixPreview{}, err
	}
	if !ok {
		return model.FixPreview{}, fmt.Errorf("no fix available for %s", f.ID)
	}

	// Report the classified kind, not the registry's raw one: classify may
	// hold a fix at Review that the registry shapes as Auto, and a preview
	// labelled "Auto-fix" next to a finding labelled "Review" would be a
	// contradiction the user has to resolve.
	preview := model.FixPreview{FindingID: f.ID, Label: fx.Label, Kind: classifiedKind(f.Remediation, fx.Kind)}
	for i, a := range fx.Actions {
		ap := model.ActionPreview{Index: i, Label: a.Label, Warning: a.Warning}
		switch a.Kind {
		case fix.ActionEdit:
			ap.Type = "edit"
			ap.Path = a.Path
			d, err := previewEdit(a)
			if err != nil {
				return model.FixPreview{}, err
			}
			ap.Diff = d
		case fix.ActionExec:
			ap.Type = "exec"
			ap.Commands = a.Commands
		case fix.ActionMode:
			ap.Type = "mode"
			d, err := previewMode(a)
			if err != nil {
				return model.FixPreview{}, err
			}
			ap.Diff = d
		default:
			return model.FixPreview{}, fmt.Errorf("action %d of %s has unknown kind %v", i, f.ID, a.Kind)
		}
		preview.Actions = append(preview.Actions, ap)
	}
	return preview, nil
}

// previewEdit computes an edit action's diff purely: read the file, run the
// pure Transform on a copy, diff the two. The live file is never written.
func previewEdit(a fix.Action) (string, error) {
	orig, err := os.ReadFile(a.Path) //nolint:gosec // path from a discovered finding
	if err != nil {
		return "", err
	}
	next, err := a.Transform(orig)
	if err != nil {
		return "", err
	}
	return diff.Unified(a.Path, string(orig), string(next)), nil
}

// modeChange is one file whose permission bits a mode action would alter.
type modeChange struct {
	path     string
	from, to fs.FileMode
}

// planModes stats every path and computes its new mode, purely. It reports
// only the paths that would actually change, so a fix cannot claim credit
// for files that were already compliant.
//
// A stat failure aborts the whole plan rather than skipping the file: a fix
// that silently tightened three of four files would report success while
// leaving the fourth exposed.
func planModes(a fix.Action) ([]modeChange, error) {
	var changes []modeChange
	for _, p := range a.Paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		cur := fi.Mode()
		next := a.Mode(cur)
		if next != cur {
			changes = append(changes, modeChange{path: p, from: cur, to: next})
		}
	}
	return changes, nil
}

// previewMode renders a mode action as a table. It only stats; the live
// files are never chmod'ed, mirroring previewEdit's purity.
//
// diff.Unified is no use here — it returns "" when the bytes match, and a
// mode change leaves them identical.
func previewMode(a fix.Action) (string, error) {
	changes, err := planModes(a)
	if err != nil {
		return "", err
	}
	if len(changes) == 0 {
		return "Permissions are already as strict as required.", nil
	}
	width := 0
	for _, c := range changes {
		if len(c.path) > width {
			width = len(c.path)
		}
	}
	var b strings.Builder
	for _, c := range changes {
		fmt.Fprintf(&b, "%-*s  %#o → %#o\n", width, c.path, c.from.Perm(), c.to.Perm())
	}
	return b.String(), nil
}

// ApplyFix applies one action of a finding's fix through the single
// backup→apply→checkpoint→mark-fixed→rescore pipeline, and returns the
// outcome. It is the ONLY path that mutates the host.
func (e *Engine) ApplyFix(ctx context.Context, f model.Finding, actionIdx int) (model.FixOutcome, error) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	return e.applyFix(ctx, f, actionIdx)
}

// applyFix is ApplyFix's body, with the caller holding applyMu. ApplyBatch
// applies many fixes under one lock and calls this directly; sync.Mutex is
// not reentrant, so the exported entry point can never be the one that loops.
func (e *Engine) applyFix(ctx context.Context, f model.Finding, actionIdx int) (model.FixOutcome, error) {
	fx, ok, err := e.buildFix(f)
	if err != nil {
		return model.FixOutcome{}, err
	}
	if !ok {
		return model.FixOutcome{}, fmt.Errorf("no fix available for %s", f.ID)
	}
	if actionIdx < 0 || actionIdx >= len(fx.Actions) {
		return model.FixOutcome{}, fmt.Errorf("action index %d out of range for %s", actionIdx, f.ID)
	}
	action := fx.Actions[actionIdx]

	var outcome model.FixOutcome
	switch action.Kind {
	case fix.ActionEdit:
		outcome, err = e.applyEdit(f, fx, action)
	case fix.ActionExec:
		outcome, err = e.applyExec(ctx, f, fx, action)
	case fix.ActionMode:
		outcome, err = e.applyMode(f, fx, action)
	default:
		err = fmt.Errorf("action %d of %s has unknown kind %v", actionIdx, f.ID, action.Kind)
	}
	if err != nil {
		return model.FixOutcome{Success: false, Error: err.Error()}, err
	}

	// Mark the finding fixed, cascade to same-service siblings sharing the
	// fix, and rescore — all inside the engine so no UI reimplements it.
	outcome.AlsoFixed = e.markFixed(f)
	outcome.Success = true
	outcome.NewScore = e.rescore()
	return outcome, nil
}

func (e *Engine) applyEdit(f model.Finding, fx fix.Fix, a fix.Action) (model.FixOutcome, error) {
	orig, err := os.ReadFile(a.Path) //nolint:gosec // path from a discovered finding
	if err != nil {
		return model.FixOutcome{}, err
	}
	next, err := a.Transform(orig)
	if err != nil {
		return model.FixOutcome{}, err
	}
	d := diff.Unified(a.Path, string(orig), string(next))

	// Back up the original before writing anything.
	cp := history.Checkpoint{
		ID:             history.NewID(f.ID),
		FindingID:      f.ID,
		FindingKey:     f.Key(),
		Label:          fx.Label,
		CreatedAt:      time.Now(),
		Diff:           d,
		RestartService: f.Service,
		// Record what this fix is about to write, so a later rollback can
		// tell "still exactly as hostveil left it" from "the operator has
		// edited this since" and decline rather than silently discard their
		// work. Computed before the write so the checkpoint is complete
		// before anything on the host changes.
		AppliedSHA256: map[string]string{a.Path: history.SHA256Hex(next)},
	}
	saved, err := e.store.Save(cp, map[string][]byte{a.Path: orig})
	if err != nil {
		return model.FixOutcome{}, fmt.Errorf("backup failed, not applying: %w", err)
	}

	mode := os.FileMode(0o644)
	if fi, err := os.Stat(a.Path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileAtomic(a.Path, next, mode); err != nil {
		return model.FixOutcome{}, err
	}

	return model.FixOutcome{Diff: d, CheckpointID: saved.ID, RestartHint: f.Service}, nil
}

// writeFileAtomic replaces path's contents in one step: write a temporary
// file beside it, then rename over the target.
//
// os.WriteFile truncates and then writes, so a crash or power loss between
// the two leaves a half-written or empty file. For the files hostveil edits
// that is not a cosmetic failure — a truncated /etc/ssh/sshd_config can mean
// sshd refuses to start and nobody can log in to the host to repair it. The
// checkpoint still holds the original, but reaching it requires the access
// the truncated file just took away. rename(2) is atomic within a
// filesystem, so a reader sees either the old file or the new one.
//
// The temporary lives in the target's own directory so the rename never
// crosses a filesystem boundary, and it is cleaned up on any failure.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".hostveil-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	// CreateTemp makes the file 0600; carry the original's mode across so the
	// rename does not silently tighten or loosen it.
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	// A rename replaces the inode, so the new file carries the temporary's
	// ownership rather than the original's. hostveil runs as root, so without
	// this a fix to a compose file owned by the operator's own account would
	// hand it to root and lock them out of editing their own file. Failing to
	// preserve ownership is an error, not something to do quietly.
	if err := preserveOwner(tmp, path); err != nil {
		_ = tmp.Close()
		return err
	}
	// Flush to disk before the rename. Without it the rename can land while
	// the contents are still in the page cache, which on a crash yields the
	// new name pointing at empty data — the very outcome this avoids.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// applyMode tightens permission bits, following applyEdit's order: record
// what is needed to undo it, refuse to proceed if that record cannot be
// written, and only then touch the host.
//
// The checkpoint stores modes without blobs. Backing up the contents just to
// undo a chmod would copy files like /etc/shadow into the checkpoint
// directory, which is a worse outcome than the finding.
func (e *Engine) applyMode(f model.Finding, fx fix.Fix, a fix.Action) (model.FixOutcome, error) {
	changes, err := planModes(a)
	if err != nil {
		return model.FixOutcome{}, err
	}
	if len(changes) == 0 {
		return model.FixOutcome{}, fmt.Errorf("permissions on %v are already as strict as required", a.Paths)
	}

	summary, err := previewMode(a)
	if err != nil {
		return model.FixOutcome{}, err
	}

	prior := make(map[string]os.FileMode, len(changes))
	for _, c := range changes {
		prior[c.path] = c.from
	}
	cp := history.Checkpoint{
		ID:         history.NewID(f.ID),
		FindingID:  f.ID,
		FindingKey: f.Key(),
		Label:      fx.Label,
		CreatedAt:  time.Now(),
		Diff:       summary,
	}
	saved, err := e.store.SaveModes(cp, prior)
	if err != nil {
		return model.FixOutcome{}, fmt.Errorf("backup failed, not applying: %w", err)
	}

	for _, c := range changes {
		if err := os.Chmod(c.path, c.to); err != nil {
			return model.FixOutcome{}, err
		}
	}
	return model.FixOutcome{Diff: summary, CheckpointID: saved.ID}, nil
}

func (e *Engine) applyExec(ctx context.Context, f model.Finding, fx fix.Fix, a fix.Action) (model.FixOutcome, error) {
	for _, cmd := range a.Commands {
		if len(cmd) == 0 {
			continue
		}
		if _, err := e.runner.Run(ctx, cmd[0], cmd[1:]...); err != nil {
			return model.FixOutcome{}, fmt.Errorf("command %v failed: %w", cmd, err)
		}
	}
	// Exec fixes are not file-backed, so there is no rollback checkpoint;
	// record the commands for the history log.
	cp := history.Checkpoint{
		ID:         history.NewID(f.ID),
		FindingID:  f.ID,
		FindingKey: f.Key(),
		Label:      fx.Label,
		CreatedAt:  time.Now(),
		Commands:   a.Commands,
	}
	if _, err := e.store.Save(cp, nil); err != nil {
		return model.FixOutcome{}, err
	}
	// CheckpointID left empty: nothing to auto-roll-back for exec.
	return model.FixOutcome{}, nil
}

// ApplyBatch applies every Auto (single-action) fix among the given
// findings in one call, skipping Review fixes (which need a choice) and
// anything without an auto fix. It is the shared implementation behind
// "fix everything safe", so no UI reimplements the batch loop.
func (e *Engine) ApplyBatch(ctx context.Context, findings []model.Finding) model.BatchOutcome {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	out := model.BatchOutcome{Failed: map[string]string{}}
	for _, f := range findings {
		if f.Fixed || f.Remediation != model.RemediationAuto {
			out.Skipped = append(out.Skipped, f.ID)
			continue
		}
		fx, ok, err := e.buildFix(f)
		if !ok || err != nil || len(fx.Actions) != 1 {
			out.Skipped = append(out.Skipped, f.ID)
			continue
		}
		if _, err := e.applyFix(ctx, f, 0); err != nil {
			out.Failed[f.ID] = err.Error()
			continue
		}
		out.Applied = append(out.Applied, f.ID)
	}
	out.NewScore = e.rescore()
	return out
}

// Rollback restores a checkpoint's files, then un-marks the finding the
// checkpoint fixed and rescores — the exact inverse of ApplyFix's
// mark-fixed→rescore tail. Doing it here rather than leaving it to a
// re-scan is what makes rollback correct in a long-lived TUI or web
// session, where the in-memory report would otherwise keep reporting a
// finding as fixed after its fix had been undone.
func (e *Engine) Rollback(id string) (model.RollbackOutcome, error) {
	return e.rollback(id, false)
}

// IsExternalEdit reports whether a rollback was declined because the file
// changed after the fix wrote it, rather than having failed.
//
// It exists because the UIs cannot answer this themselves: the layering
// tests forbid internal/ui/* from importing internal/history, so they have
// no access to the error type. Without this they would be left matching on
// the message text, which silently stops working the day the wording is
// improved. The distinction matters — a declined rollback is a question for
// the user, not an error to report.
func IsExternalEdit(err error) bool {
	var e *history.ExternalEditError
	return errors.As(err, &e)
}

// RollbackForce restores a checkpoint even when a file changed after the fix
// wrote it, discarding those changes. Rollback itself writes no checkpoint,
// so this is one-way — a UI must have said what is being discarded before
// calling it.
func (e *Engine) RollbackForce(id string) (model.RollbackOutcome, error) {
	return e.rollback(id, true)
}

func (e *Engine) rollback(id string, force bool) (model.RollbackOutcome, error) {
	// Restoring a file is a host mutation like any other, and it un-marks a
	// finding and rescores afterwards. Same lock as apply, or a rollback
	// racing a fix to the same path could interleave their writes.
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	restore := e.store.Rollback
	if force {
		restore = e.store.RollbackForce
	}
	cp, err := restore(id)
	if err != nil {
		return model.RollbackOutcome{}, err
	}
	out := model.RollbackOutcome{CheckpointID: cp.ID, RestartService: cp.RestartService}
	for _, bf := range cp.Files {
		out.RestoredFiles = append(out.RestoredFiles, bf.Path)
	}
	out.Unfixed = e.unmarkFixed(cp)
	out.NewScore = e.rescore()
	return out, nil
}

// unmarkFixed clears the Fixed flag on the finding a checkpoint fixed, so
// it reappears in every UI's active list. It matches on the full
// source|id|service key where the checkpoint has one, falling back to the
// bare finding ID for checkpoints written before FindingKey existed.
func (e *Engine) unmarkFixed(cp history.Checkpoint) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var unfixed []string
	for i := range e.current.Findings {
		f := &e.current.Findings[i]
		if !f.Fixed {
			continue
		}
		if cp.FindingKey != "" && f.Key() != cp.FindingKey {
			continue
		}
		if cp.FindingKey == "" && f.ID != cp.FindingID {
			continue
		}
		f.Fixed = false
		unfixed = append(unfixed, f.ID)
	}
	return unfixed
}

// ListCheckpoints returns saved restore points, newest first, as model
// values so every UI can render the applied-fix log without reaching into
// internal/history.
func (e *Engine) ListCheckpoints() ([]model.Checkpoint, error) {
	cps, err := e.store.List()
	if err != nil {
		return nil, err
	}
	out := make([]model.Checkpoint, 0, len(cps))
	for _, cp := range cps {
		out = append(out, toModelCheckpoint(cp))
	}
	return out, nil
}

func toModelCheckpoint(cp history.Checkpoint) model.Checkpoint {
	out := model.Checkpoint{
		ID:             cp.ID,
		FindingID:      cp.FindingID,
		Label:          cp.Label,
		CreatedAt:      cp.CreatedAt,
		Reversible:     cp.Reversible(),
		Diff:           cp.Diff,
		RestartService: cp.RestartService,
		Commands:       cp.Commands,
	}
	for _, bf := range cp.Files {
		out.Files = append(out.Files, bf.Path)
	}
	return out
}

func (e *Engine) buildFix(f model.Finding) (fix.Fix, bool, error) {
	if e.fixes == nil {
		return fix.Fix{}, false, nil
	}
	return e.fixes.Build(f)
}

// markFixed marks the target finding fixed in the current report. Richer
// cross-finding cascade and re-scan verification arrive in a later phase;
// here the applied finding alone is marked, and its return value is the
// list of additional findings marked (currently none).
func (e *Engine) markFixed(target model.Finding) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.current.Findings {
		f := &e.current.Findings[i]
		if !f.Fixed && f.Key() == target.Key() {
			f.Fixed = true
		}
	}
	return nil
}

func (e *Engine) rescore() model.ScoreBreakdown {
	e.mu.Lock()
	defer e.mu.Unlock()
	states := make(map[model.Source]model.ScanState, len(e.current.Domains))
	for _, d := range e.current.Domains {
		states[d.Source] = d.State
	}
	e.current.Score = model.ScoreReport(e.current.Findings, states)
	return e.current.Score
}
