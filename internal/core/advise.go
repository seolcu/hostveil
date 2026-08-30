package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// fixableActive is what Advise judges — active findings with a real
// Benefit/SideEffect to weigh. Manual and Unavailable findings have
// nothing to apply (WhyNoFix already explains those), so they're excluded
// here rather than sent to a model with nothing to say about them.
func fixableActive(findings []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if f.Active() && f.IsFixable() {
			out = append(out, f)
		}
	}
	model.SortFindings(out)
	return out
}

// plainAdvice renders the deterministic listing every Advise call carries
// regardless of AI: what each fixable finding's fix would get the operator
// and cost them, restated in one place. Useful on its own with ai.Noop, the
// same invariant Explain already holds to.
func plainAdvice(findings []model.Finding) string {
	if len(findings) == 0 {
		return "No active findings have a registered fix right now."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d finding(s) with a registered fix, and their trade-off:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "[%s] %s", strings.ToUpper(f.Severity.String()), f.Title)
		if f.Service != "" {
			fmt.Fprintf(&b, " (%s)", f.Service)
		}
		b.WriteString("\n")
		if f.FixBenefit != "" {
			fmt.Fprintf(&b, "  Benefit: %s\n", f.FixBenefit)
		}
		if f.FixSideEffect != "" {
			fmt.Fprintf(&b, "  Side effect: %s\n", f.FixSideEffect)
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}

// Advise judges a whole set of findings at once — "which of these fixes
// make sense here, and which don't" — against the operator's own saved
// description of this host (AIContext). findings is caller-supplied,
// mirroring ApplyBatch's shape, rather than read from e.Current(): the
// caller (a fresh scan in the CLI, the live report in the TUI/web) already
// knows which report it means.
func (e *Engine) Advise(ctx context.Context, findings []model.Finding, useAI bool) model.Advice {
	fixable := fixableActive(findings)
	adv := model.Advice{Plain: plainAdvice(fixable)}
	if !useAI || len(fixable) == 0 {
		return adv
	}
	if e.ai == nil || !e.ai.Available(ctx) {
		adv.AIError = "no AI provider is reachable (check HOSTVEIL_AI_PROVIDER and its credentials)"
		return adv
	}
	text, err := e.ai.Advise(ctx, fixable, e.AIContext())
	if err != nil {
		adv.AIError = err.Error()
		return adv
	}
	adv.AI = strings.TrimSpace(text)
	return adv
}
