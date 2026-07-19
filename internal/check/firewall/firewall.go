// Package firewall implements a native host-firewall checker. It probes
// ufw, firewalld, and nftables to decide whether any firewall is actively
// filtering traffic; if none is, that absence is itself the finding.
package firewall

import (
	"context"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports whether the host has an active firewall.
type Checker struct{}

// New returns a firewall checker.
func New() *Checker { return &Checker{} }

// Source identifies the firewall domain.
func (*Checker) Source() model.Source { return model.SourceFirewall }

// Available is always true: the absence of a firewall is a finding, so
// there is always something to report.
func (*Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	return true, ""
}

// Check probes the known firewall front-ends and, if none is active,
// emits a single finding.
//
// When a tool is installed but every probe fails — `ufw status` and
// `nft list ruleset` both need root — the honest answer is "cannot tell",
// not "no firewall". Reporting the finding there would accuse a properly
// firewalled host of being wide open purely because the scan lacked
// privileges.
func (*Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	switch status, _ := probe(ctx, env.Runner); status {
	case StatusActive:
		return nil, nil // the good case: no finding
	case StatusUnknown:
		return nil, &check.PartialError{
			Reason: "cannot read firewall state — re-run with sudo to check the host firewall",
		}
	}
	return []model.Finding{
		model.NewFinding("firewall.inactive", "No active host firewall",
			model.SeverityHigh, model.SourceFirewall, model.RemediationReview,
			model.WithDescription("Without a firewall, every port a service binds to 0.0.0.0 is reachable from any network the host is on. A firewall is your backstop when a container or service is accidentally exposed."),
			model.WithHowToFix("Enable a firewall that defaults to denying inbound traffic and allow only what you need (e.g. SSH). Important: allow your SSH port before enabling the firewall so you do not lock yourself out."),
			model.WithEvidence("available", strings.Join(availableTools(env.Runner), ", ")),
		),
	}, nil
}

// Status is the outcome of probing the host's firewall front-ends.
type Status int

const (
	// StatusInactive means the probes ran and found no firewall filtering.
	StatusInactive Status = iota
	// StatusActive means a supported firewall is actively filtering.
	StatusActive
	// StatusUnknown means a firewall tool is installed but could not be
	// queried — almost always missing root. It is deliberately distinct
	// from Inactive: "I could not look" is not evidence of absence.
	StatusUnknown
)

// Probe reports whether any supported host firewall is actively filtering,
// and which one. It is exported so other checkers (e.g. the ports checker)
// can treat an active firewall as a backstop when deciding how loudly to flag
// an exposed listener, reusing this package's probing rather than duplicating
// it. Callers must distinguish StatusUnknown from StatusInactive before
// drawing any conclusion from it.
func Probe(ctx context.Context, r platform.CommandRunner) (Status, string) {
	return probe(ctx, r)
}

// probe runs each installed front-end's query in turn. A tool that is present
// but errors is recorded as unreadable rather than as a negative answer.
func probe(ctx context.Context, r platform.CommandRunner) (Status, string) {
	unreadable := false

	query := func(tool, which string, args []string, active func(string) bool) (Status, string) {
		if !platform.Has(r, tool) {
			return StatusInactive, ""
		}
		out, err := r.Run(ctx, tool, args...)
		if err != nil {
			unreadable = true
			return StatusInactive, ""
		}
		if active(string(out)) {
			return StatusActive, which
		}
		return StatusInactive, ""
	}

	if st, which := query("ufw", "ufw", []string{"status"}, func(s string) bool {
		return strings.Contains(strings.ToLower(s), "status: active")
	}); st == StatusActive {
		return st, which
	}
	if st, which := query("firewall-cmd", "firewalld", []string{"--state"}, func(s string) bool {
		return strings.Contains(s, "running")
	}); st == StatusActive {
		return st, which
	}
	if st, which := query("nft", "nftables", []string{"list", "ruleset"}, hasHostFirewall); st == StatusActive {
		return st, which
	}

	// Only claim "no firewall" if every installed tool actually answered.
	if unreadable {
		return StatusUnknown, ""
	}
	return StatusInactive, ""
}

// hasHostFirewall reports whether an nft ruleset contains an actual
// host-level input firewall — a base chain hooked at input whose default
// policy drops or rejects traffic (what ufw, firewalld, and hand-written
// nftables firewalls install). It deliberately does NOT count the tables
// Docker adds for container networking: those hook prerouting/forward/
// postrouting and never set an input drop policy, so a plain Docker host
// with no firewall must still be flagged. Matching any "table " (the old
// behavior) silently suppressed the finding on every Docker host.
func hasHostFirewall(out string) bool {
	lower := strings.ToLower(out)
	inChain := false
	for _, line := range strings.Split(lower, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "chain ") {
			inChain = false
		}
		if strings.Contains(line, "hook input") {
			inChain = true
		}
		if inChain && (strings.Contains(line, "policy drop") || strings.Contains(line, "policy reject")) {
			return true
		}
	}
	return false
}

func availableTools(r platform.CommandRunner) []string {
	var tools []string
	for _, t := range []string{"ufw", "firewall-cmd", "nft"} {
		if platform.Has(r, t) {
			tools = append(tools, t)
		}
	}
	if len(tools) == 0 {
		return []string{"none installed"}
	}
	return tools
}
