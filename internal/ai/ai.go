// Package ai provides OPTIONAL, advisory-only explanations. Everything
// hostveil does — detection, scoring, fixes — works with no AI at all;
// this only adds a plain-language second opinion when the user opts in.
// HOSTVEIL_AI_PROVIDER (see FromEnv) selects the backend and defaults to a
// local LLM (Ollama), so nothing leaves the host unless an operator names
// an off-host provider explicitly. AI is never allowed to drive an action.
package ai

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// Explainer turns a finding into an extra plain-language explanation, and
// can also weigh a fix's trade-off against a description of the host it
// would run on.
type Explainer interface {
	// Available reports whether the provider can be reached right now.
	Available(ctx context.Context) bool
	// Explain returns an advisory explanation for the finding. siteContext
	// is the operator's own description of this host (ai.LoadContext),
	// or "" if none has been set — see buildPrompt for what changes when
	// it's given.
	Explain(ctx context.Context, f model.Finding, siteContext string) (string, error)
	// Advise judges a whole set of findings at once — "which of these
	// fixes make sense here, and which don't" — under the same siteContext
	// convention as Explain.
	Advise(ctx context.Context, findings []model.Finding, siteContext string) (string, error)
}

// Noop is the default provider used when AI is disabled: always
// unavailable, never returns anything.
type Noop struct{}

// Available always reports false.
func (Noop) Available(context.Context) bool { return false }

// Explain returns an empty explanation.
func (Noop) Explain(context.Context, model.Finding, string) (string, error) { return "", nil }

// Advise returns an empty verdict.
func (Noop) Advise(context.Context, []model.Finding, string) (string, error) { return "", nil }

// buildPrompt composes the advisory prompt for one finding. It deliberately
// sends only the finding's human-readable fields — title, description,
// suggested fix, service, and its fix's Benefit/SideEffect — and never raw
// evidence values, so secrets and paths captured as evidence do not leave
// the host.
//
// siteContext, when set, is the operator's own one-line description of
// this host (internal/ai/context.go). It is what turns a generic
// explanation into a situational one: cve.outdated-image's fix is
// attractive on a self-hosted box that wants CVE patches fast and risky on
// one that is stable today, and hostveil has no way to know which side of
// that this host is on without being told.
func buildPrompt(f model.Finding, siteContext string) string {
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
	if f.FixBenefit != "" {
		fmt.Fprintf(&b, "Applying the fix gets you: %s\n", f.FixBenefit)
	}
	if f.FixSideEffect != "" {
		fmt.Fprintf(&b, "Applying the fix costs: %s\n", f.FixSideEffect)
	}
	if siteContext != "" {
		fmt.Fprintf(&b, "\nThe operator describes this host as: %q\n", siteContext)
		b.WriteString("Given that, end your answer with one short sentence starting with \"For this host:\" " +
			"judging whether applying the fix makes sense here or is worth reconsidering.\n")
	}
	return b.String()
}

// buildAdvisePrompt composes the advisory prompt for a whole batch of
// findings at once — the same redaction discipline as buildPrompt, extended
// to a list. Asked to keep to one line per finding so the answer stays
// scannable regardless of how many are sent.
func buildAdvisePrompt(findings []model.Finding, siteContext string) string {
	var b strings.Builder
	b.WriteString("You are a friendly security assistant helping someone who self-hosts on Linux but is not a security expert. ")
	b.WriteString("Below is a list of security findings hostveil can fix, and what applying each fix would get them and cost them.\n")
	if siteContext != "" {
		fmt.Fprintf(&b, "The operator describes this host as: %q. ", siteContext)
		b.WriteString("For each finding, give a one-line verdict — Apply, Skip, or Depends — and one short reason tailored to that description.\n")
	} else {
		b.WriteString("No description of the host was given, so judge generally: call out any fix whose cost looks like it could plausibly outweigh its benefit on an average self-hosted server, and say the rest look fine to apply.\n")
	}
	b.WriteString("Keep the whole answer under 500 words, one line per finding, no preamble.\n\n")
	for i, f := range findings {
		fmt.Fprintf(&b, "%d. %s", i+1, f.Title)
		if f.Service != "" {
			fmt.Fprintf(&b, " (%s)", f.Service)
		}
		b.WriteString("\n")
		if f.FixBenefit != "" {
			fmt.Fprintf(&b, "   Benefit: %s\n", f.FixBenefit)
		}
		if f.FixSideEffect != "" {
			fmt.Fprintf(&b, "   Side effect: %s\n", f.FixSideEffect)
		}
	}
	return b.String()
}

// safeEndpoint appends path to a validated http(s) origin with no
// credentials, query, or fragment, then returns the joined URL. Rejecting
// those guards against a base URL smuggling a target the caller did not
// intend — an embedded password, or a query string a proxy in front of the
// provider might interpret.
func safeEndpoint(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q is not a usable http(s) origin: no credentials, query, or fragment", base)
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}
