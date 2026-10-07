package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/diff"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// ApplyFix applies one action of a finding's fix through the single
// backup→apply→checkpoint→mark-fixed→rescore pipeline, then re-checks the
// domain and rescores again if what it learned changed the answer. It is the
// ONLY path that mutates the host.
//
// The second rescore is why the tail is shaped this way. The score used to be
// computed once, inside applyFix, before anything had looked at the host — so
// a fix that writes a compose file and a fix that changes what is running
// moved the number identically, and the operator was told the finding was
// still reported by a message printed underneath a score that had already
// credited it. See model.Finding.Pending.
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
	// fix.Action.TakesEffectOn. applyFix has already read that declaration
	// into out.Pending, so this needs the sentence, not a second Build.
	if out.Verified == model.VerifyGone && out.Pending {
		out.Verified, out.VerifyNote = model.VerifyPending, out.TakesEffectOn
	}
	// Pending is monotone and only ever set by positive evidence.
	//
	// A checker that has just re-reported the finding is holding evidence the
	// host has not changed, so the score must not credit the fix — whatever
	// the fix declared about itself. VerifyUnavailable is the opposite and
	// deliberately does nothing here: "could not look" is not evidence, and
	// treating it as pending would mean re-checking made the number worse, so
	// an operator applying fixes one at a time would score below one who ran
	// `fix --all` over exactly the same fixes.
	if out.Verified == model.VerifyStillPresent && !out.Pending {
		out.Pending = true
		e.state.markFixed(f, true)
		out.NewScore = e.state.rescore()
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

	// Whether the host has actually changed, taken from the action already in
	// hand. A fix that names what puts it in force is a fix whose artifact is
	// not what the host reads, so writing it changed nothing an attacker can
	// see — and the score below must not pretend otherwise.
	//
	// Read from the fix's own declaration rather than from a re-check so that
	// it is the same answer on both paths: ApplyBatch does not verify, and a
	// rule that needed verification would have made the batch the optimistic
	// one, scoring a host higher for having fixed it in bulk.
	outcome.Pending = action.TakesEffectOn != ""
	outcome.TakesEffectOn = action.TakesEffectOn

	// Mark the finding fixed and rescore — both inside the engine so no UI
	// reimplements either.
	e.state.markFixed(f, outcome.Pending)
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
			built, ok, err = fix.Fix{}, false, e.crashError("deciding what to change", f.ID, r)
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
	next, err := e.safeTransform(a, f.ID, orig)
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
		AfterRestore:  afterRestore(a),
	}
	if a.SafeRoot != "" {
		cp.SafeRoots = map[string]string{a.Path: a.SafeRoot}
	}
	// A file that did not exist has nothing to back up, and the checkpoint
	// has to say so rather than record an empty backup: restoring an empty
	// file is not the same as restoring its absence, and a host left with a
	// zero-byte drop-in would look configured while configuring nothing.
	save := func() (history.Checkpoint, error) {
		// An irreversible edit is recorded, never backed up: a checkpoint with
		// no files lists as "not reversible" and cannot be rolled back.
		if a.Irreversible {
			cp.Commands = a.AfterWrite
			cp.AfterRestore = nil
			return e.store.Save(cp, nil)
		}
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
	write := func() error {
		if a.SafeRoot != "" {
			return platform.WriteFileAtomicBeneath(a.SafeRoot, a.Path, next, mode, orig, creating)
		}
		if creating {
			if _, err := os.Lstat(a.Path); err == nil {
				return fmt.Errorf("%s appeared after it was scanned; re-scan before fixing", a.Path)
			} else if !os.IsNotExist(err) {
				return err
			}
		} else {
			current, err := platform.ReadFileBounded(a.Path, int64(len(orig)))
			if err != nil || !bytes.Equal(current, orig) {
				return fmt.Errorf("%s changed after it was scanned; re-scan before fixing", a.Path)
			}
		}
		return platform.WriteFileAtomic(a.Path, next, mode)
	}
	if err := write(); err != nil {
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

	if err := e.runAfterWrite(ctx, a); err != nil {
		if a.Irreversible {
			// Not undone: see fix.Action.Irreversible. The file stays, the
			// record stays, and the operator is told exactly where it stopped
			// — what already ran, and what is left, starting with the step
			// that failed.
			var stop *stoppedAt
			left := a.AfterWrite
			ran := "nothing"
			if errors.As(err, &stop) {
				left = a.AfterWrite[stop.index:]
				if stop.index > 0 {
					ran = commandList(a.AfterWrite[:stop.index])
				}
			}
			return model.FixOutcome{}, fmt.Errorf("%w — %s was written and kept, and is recorded in `hostveil history`. "+
				"Already done: %s. Still to do, by hand: %s", err, a.Path, ran, commandList(left))
		}
		return model.FixOutcome{}, e.undoAfterFailedFollowUp(ctx, a, saved.ID, err)
	}

	return model.FixOutcome{Diff: d, CheckpointID: saved.ID, RestartHint: f.Service}, nil
}

// runAfterWrite runs an edit's follow-up commands, stopping at the first that
// fails.
func (e *Engine) runAfterWrite(ctx context.Context, a fix.Action) error {
	runCtx := ctx
	if a.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, a.Timeout)
		defer cancel()
	}
	return runEach(runCtx, e.runner, a.AfterWrite)
}

// runEach runs commands in order, stopping at the first that fails.
//
// Every unit a command starts has its failed state cleared first. systemd
// counts starts against a limit — docker.service allows three a minute — and
// past it refuses the next one outright, failed or not. Two hostveil paths hit
// it on a real Docker (scripts/e2e/individual.sh): the retry after a restart
// the new file broke, when the daemon's own Restart=always had already used up
// the limit, which left Docker down — the one outcome that retry exists to
// prevent; and an operator applying and rolling back daemon fixes within a
// minute, whose next fix failed with nothing wrong in it. reset-failed also
// clears the start counter, so each restart hostveil asks for is a real one.
func runEach(ctx context.Context, r platform.CommandRunner, cmds [][]string) error {
	resetFailedUnits(ctx, r, cmds)
	for i, cmd := range cmds {
		if len(cmd) == 0 {
			continue
		}
		if _, err := r.Run(ctx, cmd[0], cmd[1:]...); err != nil {
			return &stoppedAt{index: i, err: fmt.Errorf("command %v failed: %w", cmd, err)}
		}
	}
	return nil
}

// stoppedAt is a runEach failure that remembers which command it stopped at,
// so an irreversible fix can say what ran and what is left.
type stoppedAt struct {
	index int
	err   error
}

func (s *stoppedAt) Error() string { return s.err.Error() }
func (s *stoppedAt) Unwrap() error { return s.err }

// undoAfterFailedFollowUp handles an edit that landed and whose restart did
// not. The likeliest reason is the edit itself — a daemon refusing the new
// file — so the original goes back and the commands run again, which brings
// the service back under the configuration it was running before. The
// checkpoint then describes a change that is no longer on the host, so it is
// discarded the way a failed write's is.
//
// Every way this can go further wrong is named in the error rather than
// hidden, because the state it describes is one the operator has to act on.
func (e *Engine) undoAfterFailedFollowUp(ctx context.Context, a fix.Action, id string, cause error) error {
	if _, err := e.store.Rollback(id); err != nil {
		return fmt.Errorf("%w — and restoring the original %s failed too (%v); checkpoint %s still holds it, "+
			"restore it with `hostveil rollback %s`", cause, a.Path, err, id, id)
	}
	if err := e.runAfterWrite(ctx, a); err != nil {
		_ = e.store.Discard(id)
		return fmt.Errorf("%w — the original %s was restored, but running the commands again under it failed "+
			"as well (%v), so the service may be down", cause, a.Path, err)
	}
	if err := e.store.Discard(id); err != nil {
		return fmt.Errorf("%w — the original %s was restored and the service restarted under it, "+
			"but checkpoint %s could not be discarded: %v", cause, a.Path, id, err)
	}
	return fmt.Errorf("%w — nothing changed: the original %s was restored and the service restarted under it", cause, a.Path)
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
	owners := map[string]history.Owner{}
	for _, c := range changes {
		prior[c.path] = c.from
		if c.owner {
			owners[c.path] = history.Owner{UID: c.uid, GID: c.gid}
		}
	}
	cp := history.Checkpoint{
		ID:         history.NewID(f.ID),
		FindingID:  f.ID,
		FindingKey: f.Key(),
		Label:      fx.Label,
		CreatedAt:  time.Now(),
		Diff:       summary,
	}
	if a.SafeRoot != "" {
		cp.SafeRoots = make(map[string]string, len(changes))
		for _, c := range changes {
			cp.SafeRoots[c.path] = a.SafeRoot
		}
	}
	saved, err := e.store.SaveModesAndOwners(cp, prior, owners)
	if err != nil {
		return model.FixOutcome{}, fmt.Errorf("backup failed, not applying: %w", err)
	}

	for i, c := range changes {
		// Through the descriptor, not the path: planModes vetted the type,
		// but the file can be swapped for a symlink between the plan and this
		// line, and os.Chmod would follow it.
		var chmodErr error
		if a.SafeRoot != "" {
			chmodErr = platform.ChmodBeneath(a.SafeRoot, c.path, c.to)
		} else {
			chmodErr = platform.ChmodNoFollow(c.path, c.to)
		}
		if chmodErr == nil && c.owner {
			chmodErr = platform.ChownNoFollowPath(c.path, c.toUID, -1)
		}
		if chmodErr != nil {
			// The checkpoint is already on disk and covers every path in the
			// plan, so the ones that did change can still be rolled back.
			// Naming how far it got is the part that was missing: the outcome
			// said only "failed", while some files really had been tightened.
			return model.FixOutcome{}, fmt.Errorf(
				"%w — %d of %d paths were already changed; undo them with `hostveil rollback %s`",
				chmodErr, i, len(changes), saved.ID)
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
	runCtx := ctx
	if a.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, a.Timeout)
		defer cancel()
	}
	var ran [][]string
	var runErr error
	for _, cmd := range a.Commands {
		if len(cmd) == 0 {
			continue
		}
		if _, err := e.runner.Run(runCtx, cmd[0], cmd[1:]...); err != nil {
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

// takesEffectOn is gone. It built the fix a second time purely to re-read
// Action.TakesEffectOn out of an action applyFix already held in a local, and
// once that value decides the score as well as the message, the second build
// is not only wasted work but a second opinion: a registry that answered
// differently between the two calls would mark a finding pending and score it
// as though it were not. applyFix reads the action once and puts both the flag
// and the sentence on the outcome.

// afterRestore is what a rollback of a runs to put the restored file in
// force: its own AfterRestore where it declares one, otherwise the same
// commands that put the fix in force.
func afterRestore(a fix.Action) [][]string {
	if a.AfterRestore != nil {
		return a.AfterRestore
	}
	return a.AfterWrite
}

// resetFailedUnits clears systemd's failed state, and with it the start-limit
// counter, for every unit a set of commands starts or restarts. Errors are
// ignored: on a host without systemd, or for a unit that never failed, there
// is nothing to clear, and the retry that follows reports anything real.
func resetFailedUnits(ctx context.Context, r platform.CommandRunner, cmds [][]string) {
	for _, cmd := range cmds {
		if len(cmd) < 3 || cmd[0] != "systemctl" {
			continue
		}
		switch cmd[1] {
		case "restart", "start", "reload", "try-reload-or-restart", "reload-or-restart", "try-restart":
			_, _ = r.Run(ctx, "systemctl", append([]string{"reset-failed"}, cmd[2:]...)...)
		}
	}
}

// commandList renders commands the way an operator would type them.
func commandList(cmds [][]string) string {
	parts := make([]string, 0, len(cmds))
	for _, c := range cmds {
		parts = append(parts, "`"+strings.Join(c, " ")+"`")
	}
	return strings.Join(parts, ", then ")
}
