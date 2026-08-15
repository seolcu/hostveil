package core

import (
	"context"

	"github.com/seolcu/hostveil/internal/model"
)

// ApplyBatch applies every Auto (single-action) fix among the given
// findings in one call, skipping Review fixes (which need a choice) and
// anything without an auto fix. It is the shared implementation behind
// "fix everything safe", so no UI reimplements the batch loop.
func (e *Engine) ApplyBatch(ctx context.Context, findings []model.Finding) model.BatchOutcome {
	return e.applyBatch(ctx, findings, false)
}

// ApplyBatchWithReviewed is the same loop with the Review fixes included,
// each applied through its *first* alternative — which every builder in the
// registry writes as the primary remediation, the one the finding's how-to-fix
// describes.
//
// It exists because "fix everything hostveil can" and "fix everything that
// needs no human" are different requests, and only the second had a command.
// The classification does not move: a Review fix is still one that can cut off
// access to the host or has more than one defensible answer, and the caller
// has to say, in the command, that it accepts them. What changes is that
// accepting them no longer means running the tool once per finding.
//
// The batch still refuses anything the registry does not answer, so this can
// never apply a fix nobody wrote.
func (e *Engine) ApplyBatchWithReviewed(ctx context.Context, findings []model.Finding) model.BatchOutcome {
	return e.applyBatch(ctx, findings, true)
}

func (e *Engine) applyBatch(ctx context.Context, findings []model.Finding, reviewed bool) model.BatchOutcome {
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
		eligible := f.Remediation == model.RemediationAuto ||
			(reviewed && f.Remediation == model.RemediationReview)
		// Fixed, not !Active: this asks whether hostveil has already applied
		// something here, and for a pending fix it has. Asking Active would
		// re-apply it on every batch until the operator restarted the service,
		// writing a checkpoint each time over a file that had not changed.
		if f.Fixed || !eligible {
			out.Skipped = append(out.Skipped, f.ID)
			continue
		}
		fx, ok, err := e.buildFix(f)
		// A fix that exists and could not be built is a defect in hostveil,
		// not a property of the finding — a malformed registration, or
		// evidence the checker did not write. Reporting it as Skipped made it
		// indistinguishable from "there is no fix for this", which is the one
		// reading that guarantees nobody ever looks.
		if err != nil {
			out.Failed[f.ID] = err.Error()
			continue
		}
		if !ok || len(fx.Actions) == 0 {
			out.Skipped = append(out.Skipped, f.ID)
			continue
		}
		// An Auto fix is one action by definition (fix.Validate enforces it),
		// and a batch that silently picked one of several would be choosing
		// for the operator. A reviewed batch takes the first alternative
		// because that is where every builder puts the primary remediation.
		if !reviewed && len(fx.Actions) != 1 {
			out.Skipped = append(out.Skipped, f.ID)
			continue
		}
		res, err := e.applyFix(ctx, f, 0)
		if err != nil {
			out.Failed[f.ID] = err.Error()
			continue
		}
		out.Applied = append(out.Applied, f.ID)
		// A subset of Applied, not a fourth bucket: the fix was applied, and
		// what is left is the restart. The batch does not re-check, so this
		// comes from the action's own TakesEffectOn — which is the whole
		// reason that declaration lives on the fix rather than being derived
		// from a re-check nobody runs here.
		if res.Pending {
			out.Pending = append(out.Pending, f.ID)
		}
	}
	out.NewScore = e.state.rescore()
	// Rendered here, after the score, so every interface reports the same
	// outcome rather than four descriptions of it.
	out.Message = out.Summary()
	return out
}
