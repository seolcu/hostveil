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

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/diff"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
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
	orig, _, err := readEditTarget(a)
	if err != nil {
		return "", err
	}
	next, err := a.Transform(orig)
	if err != nil {
		return "", err
	}
	return diff.Unified(a.Path, string(orig), string(next)), nil
}

// readEditTarget reads an edit action's file, reporting whether the action
// is about to create it.
//
// A CreateIfMissing action treats an absent file as empty input, so
// Transform composes the whole contents and the diff renders as a pure
// addition — which is exactly what the operator is being asked to approve.
// Any other read error is still an error, including for such an action: a
// permission denial or an EISDIR must not be mistaken for "not there yet"
// and answered by creating something.
func readEditTarget(a fix.Action) (data []byte, creating bool, err error) {
	data, err = os.ReadFile(a.Path) //nolint:gosec // path from a discovered finding
	switch {
	case err == nil:
		return data, false, nil
	case a.CreateIfMissing && errors.Is(err, fs.ErrNotExist):
		return nil, true, nil
	default:
		return nil, false, err
	}
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
//
// Lstat plus a type check, never Stat. Mode fixes reach into user homes
// (agent.config-perms), where the path is the account's to shape: a symlink
// left where the config file was would send root's chmod to whatever the
// link points at. Refusing loudly rather than skipping keeps the no-silent-
// partial-success rule above.
func planModes(a fix.Action) ([]modeChange, error) {
	var changes []modeChange
	for _, p := range a.Paths {
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if m := fi.Mode(); !m.IsRegular() && !m.IsDir() {
			return nil, fmt.Errorf("%s is not a regular file or directory (%v); refusing to change its mode", p, m.Type())
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
	out.VerifyMessage = out.Verified.Note(out.RestartHint)
	return out, nil
}

// verifyFix re-runs the finding's own domain and reports whether it is
// still there.
//
// It runs the one checker directly rather than going through ScanWith, for
// two reasons that are each sufficient. ScanWith takes applyMu, which
// ApplyFix already holds, so calling it here would deadlock. And a scoped
// scan replaces the current report wholesale with just that domain's
// findings — verifying an SSH fix would delete every container finding from
// the report the operator is looking at.
//
// The runner is the uncached one, deliberately. e.runner is what fixes use,
// because a cached answer would report the state of the host before the fix
// rather than after it — which is the entire question being asked.
func (e *Engine) verifyFix(ctx context.Context, f model.Finding) (model.FixVerification, string) {
	if e.registry == nil {
		return model.VerifyNotRun, ""
	}
	var target check.Checker
	for _, c := range e.registry.Checkers() {
		if c.Source() == f.Source {
			target = c
		}
	}
	if target == nil {
		return model.VerifyUnavailable, "no checker is registered for this domain"
	}

	env := platform.Detect(ctx, e.runner)
	results := check.NewRegistry(target).Run(ctx, env, nil)
	if len(results) != 1 {
		return model.VerifyUnavailable, "the re-check did not run"
	}
	r := results[0]

	// The same rule the scan itself follows. A checker that was skipped,
	// failed, or covered only part of its ground has not established that
	// the finding is gone — and "could not look" must never read as either
	// answer.
	//
	// Complete, not Ran: a degraded re-check *did* run, so Ran accepts it,
	// but it covered only part of its ground and the finding may live in
	// the part it missed.
	if !r.State.Complete() {
		reason := r.Reason
		if reason == "" {
			reason = "the re-check could not cover this domain"
		}
		return model.VerifyUnavailable, reason
	}

	for _, got := range validFindings(r.Findings) {
		if got.Key() == f.Key() {
			return model.VerifyStillPresent, ""
		}
	}
	return model.VerifyGone, ""
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
	e.markFixed(f)
	outcome.Success = true
	outcome.NewScore = e.rescore()
	return outcome, nil
}

func (e *Engine) applyEdit(ctx context.Context, f model.Finding, fx fix.Fix, a fix.Action) (model.FixOutcome, error) {
	orig, creating, err := readEditTarget(a)
	if err != nil {
		return model.FixOutcome{}, err
	}
	next, err := a.Transform(orig)
	if err != nil {
		return model.FixOutcome{}, err
	}
	d := diff.Unified(a.Path, string(orig), string(next))

	// Before the backup, and long before the write: a fix that would produce
	// a file the service refuses must not touch the host at all.
	if err := e.verifyEdit(ctx, a, orig, next); err != nil {
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
	if err := platform.WriteFileAtomic(a.Path, next, mode); err != nil {
		return model.FixOutcome{}, err
	}

	return model.FixOutcome{Diff: d, CheckpointID: saved.ID, RestartHint: f.Service}, nil
}

// verifyEdit checks that the bytes an edit action produced are something the
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
func (e *Engine) verifyEdit(ctx context.Context, a fix.Action, orig, next []byte) error {
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

// ApplyBatch applies every Auto (single-action) fix among the given
// findings in one call, skipping Review fixes (which need a choice) and
// anything without an auto fix. It is the shared implementation behind
// "fix everything safe", so no UI reimplements the batch loop.
func (e *Engine) ApplyBatch(ctx context.Context, findings []model.Finding) model.BatchOutcome {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	out := model.BatchOutcome{Failed: map[string]string{}}
	for _, f := range findings {
		// Between fixes, not during one. A fix is backup→write→checkpoint and
		// must finish what it started; the safe place to stop is the gap
		// before the next one. Everything after the interruption lands in
		// Skipped, and Interrupted says those were never reached rather than
		// judged ineligible — otherwise a batch cut short reads exactly like
		// one that ran to completion.
		if ctx.Err() != nil {
			out.Interrupted = true
			out.Skipped = append(out.Skipped, f.ID)
			continue
		}
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
//
// A checkpoint whose metadata cannot be read comes back as a non-nil error
// *alongside* the ones that could, because the list is still worth showing
// and the operator still needs telling that part of their recovery history is
// gone. Use IsIncompleteHistory to tell that from an outright failure.
func (e *Engine) ListCheckpoints() ([]model.Checkpoint, error) {
	cps, err := e.store.List()
	if err != nil && !history.IsDamaged(err) {
		return nil, err
	}
	out := make([]model.Checkpoint, 0, len(cps))
	for _, cp := range cps {
		out = append(out, toModelCheckpoint(cp))
	}
	return out, err
}

// IsIncompleteHistory reports whether an error from ListCheckpoints means
// "some checkpoints are unreadable" rather than "the list failed".
//
// It exists for the same reason IsExternalEdit does: the layering tests
// forbid internal/ui/* from importing internal/history, so a UI has no access
// to the error type and would otherwise be left matching on message text.
func IsIncompleteHistory(err error) bool { return history.IsDamaged(err) }

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

// markFixed marks the target finding fixed in the current report.
//
// It used to return "the list of additional findings marked (currently
// none)" against a planned cross-finding cascade, and FixOutcome carried
// that list to the UIs as `also_fixed`. Nothing ever populated it and no
// interface ever read it, so the field promised a behaviour the engine did
// not have; both are gone. If a cascade is ever built, it should be built
// with the thing that reports it, not ahead of it.
func (e *Engine) markFixed(target model.Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.current.Findings {
		f := &e.current.Findings[i]
		if !f.Fixed && f.Key() == target.Key() {
			f.Fixed = true
		}
	}
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
