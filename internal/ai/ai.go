// Package ai provides OPTIONAL, advisory-only explanations. Everything
// hostveil does — detection, scoring, fixes — works with no AI at all;
// this only adds a plain-language second opinion when the user opts in.
// The provider defaults to a local LLM (Ollama) so nothing leaves the
// host, and it is never allowed to drive an action.
package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// Explainer turns a finding into an extra plain-language explanation.
type Explainer interface {
	// Available reports whether the provider can be reached right now.
	Available(ctx context.Context) bool
	// Explain returns an advisory explanation for the finding.
	Explain(ctx context.Context, f model.Finding) (string, error)
}

// Noop is the default provider used when AI is disabled: always
// unavailable, never returns anything.
type Noop struct{}

// Available always reports false.
func (Noop) Available(context.Context) bool { return false }

// Explain returns an empty explanation.
func (Noop) Explain(context.Context, model.Finding) (string, error) { return "", nil }

// buildPrompt composes the advisory prompt. It deliberately sends only the
// finding's human-readable fields — title, description, suggested fix,
// service — and never raw evidence values, so secrets and paths captured
// as evidence do not leave the host.
func buildPrompt(f model.Finding) string {
	var b strings.Builder
	b.WriteString("You are a friendly security assistant helping someone who self-hosts on Linux but is not a security expert. ")
	b.WriteString("Explain the following finding in plain language: what it means, why it matters, and briefly how to fix it. ")
	b.WriteString("Keep it under 120 words. Avoid jargon.\n\n")
	fmt.Fprintf(&b, "Finding: %s\n", f.Title)
	if f.Service != "" {
		fmt.Fprintf(&b, "Affected service: %s\n", f.Service)
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "Details: %s\n", f.Description)
	}
	if f.HowToFix != "" {
		fmt.Fprintf(&b, "Suggested fix: %s\n", f.HowToFix)
	}
	return b.String()
}
