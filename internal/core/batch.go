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
	out.NewScore = e.state.rescore()
	// Rendered here, after the score, so every interface reports the same
	// outcome rather than four descriptions of it.
	out.Message = out.Summary()
	return out
}
