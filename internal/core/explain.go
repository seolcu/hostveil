package core

import (
	"context"
	"strings"

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
		exp.AIError = "no AI provider is reachable (is Ollama running?)"
		return exp
	}
	text, err := e.ai.Explain(ctx, f)
	if err != nil {
		exp.AIError = err.Error()
		return exp
	}
	exp.AI = strings.TrimSpace(text)
	return exp
}

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
	return strings.TrimSpace(b.String())
}
