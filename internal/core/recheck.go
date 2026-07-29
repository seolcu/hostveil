package core

import (
	"context"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

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
