package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/seolcu/hostveil/internal/diff"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// ApplyFix applies one action of a finding's fix through the single
// backup→apply→checkpoint→mark-fixed→rescore pipeline, and returns the
// outcome. It is the ONLY path that mutates the host.
func (e *Engine) ApplyFix(ctx context.Context, f model.Finding, actionIdx int) (model.FixOutcome, error) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	out, err := e.applyFix(ctx, f, actionIdx)
	if err != nil {
		return out, err
	}
	// Verify only on the single-fix path. ApplyBatch calls applyFix in a
	// loop, and re-checking there would re-run a checker once per fix —
	// twenty compose findings would mean twenty enumerations of every
	// container on the host. A batch ends with the operator rescanning
	// anyway; a single fix is the one they are watching.
	out.Verified, out.VerifyNote = e.verifyFix(ctx, f)
	// A re-check that no longer sees the finding has established that the
	// artifact the fix wrote is correct — and where that artifact is not what
	// the host is running from, that is all it has established. See
	// fix.Action.TakesEffectOn.
	if out.Verified == model.VerifyGone {
		if effect := e.takesEffectOn(f, actionIdx); effect != "" {
			out.Verified, out.VerifyNote = model.VerifyPending, effect
		}
	}
	out.VerifyMessage = out.Verified.Note(out.RestartHint)
	return out, nil
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
		outcome, err = e.applyEdit(ctx, f, fx, action)
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

	// Mark the finding fixed and rescore — both inside the engine so no UI
	// reimplements either.
	e.state.markFixed(f)
	outcome.Success = true
	outcome.NewScore = e.state.rescore()
	return outcome, nil
}

// buildFix resolves the registered fix for a finding and checks that its
// shape matches the kind it claims.
//
// fix.Validate is the contract — Auto is exactly one action, Review is two
// or more alternatives, an edit carries a Transform, an exec carries a
// command — and until now nothing but a test ever ran it. That left the
// registry's shape guaranteed only for the representative findings
// internal/fix/fix_test.go happens to build. A registration that came out
// malformed for some other finding got no complaint at all: classify saw a
// fixable Kind and left the finding Auto, so a UI drew a fix button, and
// the first thing to notice was applyEdit calling a nil Transform. There is
// no recover on that path.
//
// A registered fix whose shape contradicts its kind is therefore an error
// rather than a fix. Reporting it as "registered, but broken" is what lets
// classify demote the finding to Manual, which is the same answer it
// already gives when no fix is registered and the same promise the rest of
// the engine makes: a UI never offers a button that leads nowhere.
func (e *Engine) buildFix(f model.Finding) (built fix.Fix, ok bool, err error) {
	if e.fixes == nil {
		return fix.Fix{}, false, nil
	}
	// The whole body, not just Build: Validate reads the shape a builder
	// returned, and a builder that half-built one is exactly the case where
	// both can go wrong. See contain.go.
	defer func() {
		if r := recover(); r != nil {
			built, ok, err = fix.Fix{}, false, crashError("deciding what to change", f.ID, r)
		}
	}()
	fx, ok, err := e.fixes.Build(f)
	if !ok || err != nil {
		return fx, ok, err
	}
	if err := fix.Validate(fx); err != nil {
		return fix.Fix{}, true, err
	}
	return fx, true, nil
}

func (e *Engine) applyEdit(ctx context.Context, f model.Finding, fx fix.Fix, a fix.Action) (model.FixOutcome, error) {
	orig, creating, err := readEditTarget(a)
	if err != nil {
		return model.FixOutcome{}, err
	}
	next, err := safeTransform(a, f.ID, orig)
	if err != nil {
		return model.FixOutcome{}, err
	}
	d := diff.Unified(a.Path, string(orig), string(next))

	// Before the backup, and long before the write: a fix that would produce
	// a file the service refuses must not touch the host at all.
	if err := e.runEditValidator(ctx, a, orig, next); err != nil {
		return model.FixOutcome{}, err
	}

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
	// A file that did not exist has nothing to back up, and the checkpoint
	// has to say so rather than record an empty backup: restoring an empty
	// file is not the same as restoring its absence, and a host left with a
	// zero-byte drop-in would look configured while configuring nothing.
	save := func() (history.Checkpoint, error) {
		if creating {
			return e.store.SaveCreations(cp, []string{a.Path})
		}
		return e.store.Save(cp, map[string][]byte{a.Path: orig})
	}
	saved, err := save()
	if err != nil {
		return model.FixOutcome{}, fmt.Errorf("backup failed, not applying: %w", err)
	}

	mode := os.FileMode(0o644)
	if fi, err := os.Stat(a.Path); err == nil {
		mode = fi.Mode().Perm()
	}
	// A file that may not exist may not have a directory either, and the two
	// are the same situation from the caller's side. The sysctl and apt
	// drop-ins land in directories every distribution ships, so this went
	// unnoticed until a systemd drop-in — /etc/systemd/system/<unit>.d/ is
	// created by whoever first overrides that unit, which is usually nobody.
	// WriteFileAtomic stages its temp file beside the target, so a missing
	// directory fails there rather than at the rename, after the checkpoint
	// is already written.
	//
	// Rollback deletes the file and leaves the directory. By then it may hold
	// a drop-in somebody else put there, and an empty .d directory changes
	// nothing about how systemd reads the unit.
	if creating {
		// G301: 0755 and not 0750, because this is a configuration directory
		// under /etc and the config in it is meant to be readable. `systemctl
		// cat` run by the operator as themselves reads the drop-in hostveil
		// wrote; at 0750 root:root it would not, and hostveil would have
		// hidden the change it just made from the person who asked for it.
		// Nothing secret is written here — the file holds one directive that
		// is also in the finding, the preview and the checkpoint.
		//nolint:gosec // G301: a config directory under /etc, readable on purpose
		if err := os.MkdirAll(filepath.Dir(a.Path), 0o755); err != nil {
			return model.FixOutcome{}, fmt.Errorf("creating the directory for %s: %w", a.Path, err)
		}
	}
	if err := platform.WriteFileAtomic(a.Path, next, mode); err != nil {
		// The checkpoint is already on disk and `hostveil history` will list
		// it as an applied, reversible fix — for a change that never landed.
		// Worse, its AppliedSHA256 permanently asserts to recordedWrites that
		// hostveil wrote bytes it did not, which weakens the external-edit
		// guard for this path from here on.
		//
		// So the checkpoint goes with the failure. applyMode reports the same
		// class of failure by naming how far it got, because its writes are
		// partial by nature; an edit is one atomic rename, so here there is
		// nothing to keep.
		if rmErr := e.store.Discard(saved.ID); rmErr != nil {
			return model.FixOutcome{}, fmt.Errorf("%w — and the backup at %s could not be discarded: %v",
				err, saved.ID, rmErr)
		}
		return model.FixOutcome{}, err
	}

	return model.FixOutcome{Diff: d, CheckpointID: saved.ID, RestartHint: f.Service}, nil
}

// runEditValidator checks that the bytes an edit action produced are something the
// service will actually accept, before they reach the live file.
//
// The validator runs twice: once on the original file, once on the new
// content, both in a temporary directory. Only a validator that accepts the
// original is trusted to reject the replacement. That control run is what
// makes this usable at all — `sshd -t` needs to read the host keys, so on a
// host where it cannot, it fails on every config including the one already
// in service. Without the control, a fix would be blocked by the checker's
// own inability to run rather than by anything wrong with the file.
//
// Checking before the write rather than after means there is nothing to undo
// when it fails: the live file was never touched.
func (e *Engine) runEditValidator(ctx context.Context, a fix.Action, orig, next []byte) error {
	if len(a.VerifyCmd) == 0 {
		return nil
	}
	if _, err := e.runner.LookPath(a.VerifyCmd[0]); err != nil {
		return nil // no validator on this host; cannot verify is not invalid
	}

	dir, err := os.MkdirTemp("", "hostveil-verify-")
	if err != nil {
		return nil // cannot stage the check; do not block the fix on it
	}
	defer func() { _ = os.RemoveAll(dir) }()

	run := func(name string, data []byte) error {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return err
		}
		argv := make([]string, len(a.VerifyCmd))
		for i, arg := range a.VerifyCmd {
			if arg == fix.VerifyPathToken {
				arg = p
			}
			argv[i] = arg
		}
		_, err := e.runner.Run(ctx, argv[0], argv[1:]...)
		return err
	}

	if err := run("before", orig); err != nil {
		// The validator rejects the file that is already in service, so it is
		// not telling us anything about our edit.
		return nil
	}
	if err := run("after", next); err != nil {
		return fmt.Errorf("%s rejects the file this fix would produce: %w", a.VerifyCmd[0], err)
	}
	return nil
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

	// From the plan already in hand, not a second one: the summary must
	// describe the changes this call is about to make.
	summary := modeTable(changes)

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

	for i, c := range changes {
		// Through the descriptor, not the path: planModes vetted the type,
		// but the file can be swapped for a symlink between the plan and this
		// line, and os.Chmod would follow it.
		if err := platform.ChmodNoFollow(c.path, c.to); err != nil {
			// The checkpoint is already on disk and covers every path in the
			// plan, so the ones that did change can still be rolled back.
			// Naming how far it got is the part that was missing: the outcome
			// said only "failed", while some files really had been tightened.
			return model.FixOutcome{}, fmt.Errorf(
				"%w — %d of %d paths were already changed; undo them with `hostveil rollback %s`",
				err, i, len(changes), saved.ID)
		}
	}
	return model.FixOutcome{Diff: summary, CheckpointID: saved.ID}, nil
}

// applyExec runs an exec action's commands in order, stopping at the first
// failure.
//
// The record is written whether or not every command succeeded, and that is
// the point. A fix like updates' — `apt-get install -y unattended-upgrades`
// then `systemctl enable --now` — changes the host on the first command; if
// the second fails, returning before the Save left the host modified with no
// history entry at all, reported only as `Success: false`. The operator was
// then told the fix failed while a package sat newly installed and unnamed.
//
// There is still no rollback checkpoint: exec actions are not file-backed
// and nothing about them can be recorded to undo. What is recorded is what
// ran, which is what someone repairing this by hand needs.
func (e *Engine) applyExec(ctx context.Context, f model.Finding, fx fix.Fix, a fix.Action) (model.FixOutcome, error) {
	var ran [][]string
	var runErr error
	for _, cmd := range a.Commands {
		if len(cmd) == 0 {
			continue
		}
		if _, err := e.runner.Run(ctx, cmd[0], cmd[1:]...); err != nil {
			runErr = fmt.Errorf("command %v failed: %w", cmd, err)
			break
		}
		ran = append(ran, cmd)
	}

	// Exec fixes are not file-backed, so there is no rollback checkpoint;
	// record the commands for the history log.
	cp := history.Checkpoint{
		ID:         history.NewID(f.ID),
		FindingID:  f.ID,
		FindingKey: f.Key(),
		Label:      fx.Label,
		CreatedAt:  time.Now(),
		Commands:   ran,
	}
	if runErr != nil {
		if len(ran) == 0 {
			// Nothing ran, so the host is untouched and there is nothing worth
			// recording. Reporting a checkpoint here would clutter the history
			// with entries that undo nothing and describe no change.
			return model.FixOutcome{}, runErr
		}
		cp.Label = fx.Label + " (partially applied)"
		if _, err := e.store.Save(cp, nil); err != nil {
			return model.FixOutcome{}, fmt.Errorf("%w (and the partial change could not be recorded: %v)", runErr, err)
		}
		return model.FixOutcome{}, fmt.Errorf("%w — %d of %d commands had already run and are recorded in `hostveil history`",
			runErr, len(ran), countCommands(a.Commands))
	}

	if _, err := e.store.Save(cp, nil); err != nil {
		return model.FixOutcome{}, err
	}
	// CheckpointID left empty: nothing to auto-roll-back for exec.
	return model.FixOutcome{}, nil
}

func countCommands(cmds [][]string) int {
	n := 0
	for _, c := range cmds {
		if len(c) > 0 {
			n++
		}
	}
	return n
}

// takesEffectOn reports what has to happen before the applied action reaches
// the host, or "" when the edit is in force as soon as it is written.
func (e *Engine) takesEffectOn(f model.Finding, actionIdx int) string {
	fx, ok, err := e.buildFix(f)
	if err != nil || !ok || actionIdx < 0 || actionIdx >= len(fx.Actions) {
		return ""
	}
	return fx.Actions[actionIdx].TakesEffectOn
}
