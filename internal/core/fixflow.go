package core

import (
	"context"
	"fmt"
	"os"
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

	preview := model.FixPreview{FindingID: f.ID, Label: fx.Label, Kind: fx.Kind}
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

// ApplyFix applies one action of a finding's fix through the single
// backup→apply→checkpoint→mark-fixed→rescore pipeline, and returns the
// outcome. It is the ONLY path that mutates the host.
func (e *Engine) ApplyFix(ctx context.Context, f model.Finding, actionIdx int) (model.FixOutcome, error) {
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
		Label:          fx.Label,
		CreatedAt:      time.Now(),
		Diff:           d,
		RestartService: f.Service,
	}
	saved, err := e.store.Save(cp, map[string][]byte{a.Path: orig})
	if err != nil {
		return model.FixOutcome{}, fmt.Errorf("backup failed, not applying: %w", err)
	}

	mode := os.FileMode(0o644)
	if fi, err := os.Stat(a.Path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.WriteFile(a.Path, next, mode); err != nil {
		return model.FixOutcome{}, err
	}

	return model.FixOutcome{Diff: d, CheckpointID: saved.ID, RestartHint: f.Service}, nil
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
		ID:        history.NewID(f.ID),
		FindingID: f.ID,
		Label:     fx.Label,
		CreatedAt: time.Now(),
		Commands:  a.Commands,
	}
	if _, err := e.store.Save(cp, nil); err != nil {
		return model.FixOutcome{}, err
	}
	// CheckpointID left empty: nothing to auto-roll-back for exec.
	return model.FixOutcome{}, nil
}

// Rollback restores a checkpoint's files and rescans nothing; the caller
// (or a re-scan) reflects the restored state.
func (e *Engine) Rollback(id string) (model.RollbackOutcome, error) {
	cp, err := e.store.Rollback(id)
	if err != nil {
		return model.RollbackOutcome{}, err
	}
	out := model.RollbackOutcome{CheckpointID: cp.ID, RestartService: cp.RestartService}
	for _, bf := range cp.Files {
		out.RestoredFiles = append(out.RestoredFiles, bf.Path)
	}
	return out, nil
}

// ListCheckpoints returns saved restore points, newest first.
func (e *Engine) ListCheckpoints() ([]history.Checkpoint, error) {
	return e.store.List()
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
	ran := make(map[model.Source]bool, len(e.current.Domains))
	for _, d := range e.current.Domains {
		ran[d.Source] = d.State.Ran()
	}
	e.current.Score = model.ScoreReport(e.current.Findings, ran)
	return e.current.Score
}
