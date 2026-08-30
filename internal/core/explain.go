package core

import (
	"context"
	"strings"

	"github.com/seolcu/hostveil/internal/ai"
	"github.com/seolcu/hostveil/internal/model"
)

// Explain returns a plain-language explanation of a finding. The
// deterministic Plain text is always produced from the finding itself.
// When useAI is true and a provider is reachable, an advisory AI
// explanation is added — advisory only; AI never drives an action.
func (e *Engine) Explain(ctx context.Context, f model.Finding, useAI bool) model.Explanation {
	exp := model.Explanation{Plain: plainExplanation(f)}
	if !useAI {
		return exp
	}
	if e.ai == nil || !e.ai.Available(ctx) {
		exp.AIError = "no AI provider is reachable (check HOSTVEIL_AI_PROVIDER and its credentials)"
		return exp
	}
	text, err := e.ai.Explain(ctx, f, e.AIContext())
	if err != nil {
		exp.AIError = err.Error()
		return exp
	}
	exp.AI = strings.TrimSpace(text)
	return exp
}

// AIContext returns the operator's own saved description of this host —
// "a personal media server, want fast security patches more than
// stability" — used to make an AI judgment situational rather than
// generic. "" means nothing has been set.
func (e *Engine) AIContext() string { return ai.LoadContext(e.store.Dir()) }

// SetAIContext records or clears the saved host description (text == ""
// clears it). It lives on Engine, not behind a UI-injected callback like
// theme/layout's Save, because the state directory is already reachable
// through e.store.Dir() — internal/core is not layering-restricted the way
// internal/ui is.
func (e *Engine) SetAIContext(text string) error { return ai.SaveContext(e.store.Dir(), text) }

// plainExplanation renders the deterministic explanation from the
// finding's own fields — always available, no AI required.
func plainExplanation(f model.Finding) string {
	var b strings.Builder
	b.WriteString(f.Title)
	b.WriteString(" — severity: " + f.Severity.String())
	if f.Service != "" {
		b.WriteString(", service: " + f.Service)
	}
	b.WriteString(".\n\n")
	if f.Description != "" {
		b.WriteString(f.Description + "\n\n")
	}
	if f.HowToFix != "" {
		b.WriteString("How to fix: " + f.HowToFix)
	}
	// Last, and only when there is one. A finding with a fix button does not
	// need to be told why it has one, and a paragraph explaining an absence
	// above the instructions for handling it would bury the actionable half.
	if f.WhyNoFix != "" {
		b.WriteString("\n\nWhy Hostveil will not do this for you: " + f.WhyNoFix)
	}
	return strings.TrimSpace(b.String())
}
