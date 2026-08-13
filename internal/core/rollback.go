package core

import (
	"errors"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

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
	// A partial restore is the one failure that still changed the host, so
	// the outcome has to survive it: the operator needs the list of files
	// that did move before they can decide anything. Everything else —
	// a declined external edit, a corrupt blob, an unreadable checkpoint —
	// happens before the first write, and there is nothing to report.
	var partial *history.PartialRestoreError
	if errors.As(err, &partial) {
		return model.RollbackOutcome{
			CheckpointID:   cp.ID,
			RestartService: cp.RestartService,
			RestoredFiles:  partial.Restored,
			FailedFiles:    partial.Failed,
		}, err
	}
	if err != nil {
		return model.RollbackOutcome{}, err
	}
	out := model.RollbackOutcome{CheckpointID: cp.ID, RestartService: cp.RestartService}
	for _, bf := range cp.Files {
		out.RestoredFiles = append(out.RestoredFiles, bf.Path)
	}
	out.Unfixed = e.state.unmarkFixed(cp)
	out.NewScore = e.state.rescore()
	return out, nil
}
