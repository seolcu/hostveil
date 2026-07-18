// Package firewall implements a native host-firewall checker. It probes
// ufw, firewalld, and nftables to decide whether any firewall is actively
// filtering traffic; if none is, that absence is itself the finding.
package firewall

import (
	"context"
	"strings"

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
func (*Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	if active, which := activeFirewall(ctx, env.Runner); active {
		_ = which // an active firewall is the good case: no finding
		return nil, nil
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

// Active reports whether any supported host firewall is actively filtering.
// It is exported so other checkers (e.g. the ports checker) can treat an
// active firewall as a backstop when deciding how loudly to flag an exposed
// listener, reusing this package's probing rather than duplicating it.
func Active(ctx context.Context, r platform.CommandRunner) bool {
	active, _ := activeFirewall(ctx, r)
	return active
}

// activeFirewall returns whether any supported firewall is actively
// filtering, and which one.
func activeFirewall(ctx context.Context, r platform.CommandRunner) (bool, string) {
	if platform.Has(r, "ufw") {
		if out, err := r.Run(ctx, "ufw", "status"); err == nil &&
			strings.Contains(strings.ToLower(string(out)), "status: active") {
			return true, "ufw"
		}
	}
	if platform.Has(r, "firewall-cmd") {
		if out, err := r.Run(ctx, "firewall-cmd", "--state"); err == nil &&
			strings.Contains(string(out), "running") {
			return true, "firewalld"
		}
	}
	if platform.Has(r, "nft") {
		if out, err := r.Run(ctx, "nft", "list", "ruleset"); err == nil && hasHostFirewall(string(out)) {
			return true, "nftables"
		}
	}
	return false, ""
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
