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
type Checker struct {
	// DaemonConfigPath is Docker's daemon.json. Overridable for tests;
	// empty means the real /etc/docker/daemon.json.
	DaemonConfigPath string
}

// New returns a firewall checker.
func New() *Checker { return &Checker{} }

func (c *Checker) daemonConfig() string {
	if c.DaemonConfigPath != "" {
		return c.DaemonConfigPath
	}
	return defaultDaemonConfig
}

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
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	switch status, which := probe(ctx, env.Runner); status {
	case StatusActive:
		// An active firewall is not the end of the question on a Docker
		// host: published container ports are accepted before ufw's rules
		// are consulted. Scoring this case clean is what let a host with an
		// open datastore outscore one running nothing at all.
		if which == "ufw" {
			return checkDockerBypass(ctx, env.Runner, c.daemonConfig())
		}
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
	// firewalld is detected by exit status, not by the text of `--state`.
	// The command exits 0 when the daemon is running and non-zero when it is
	// not, which is the only signal stable across versions: some print
	// "running" to stdout, others to stderr, and Run captures stdout only.
	// Matching the text therefore read a running firewalld as absent on every
	// host of the second kind — a High finding on a firewalled machine.
	if platform.Has(r, "firewall-cmd") {
		if _, err := r.Run(ctx, "firewall-cmd", "--state"); err != nil {
			unreadable = true
		} else {
			return StatusActive, "firewalld"
		}
	}
	if st, which := query("nft", "nftables", []string{"list", "ruleset"}, hasHostFirewall); st == StatusActive {
		return st, which
	}
	// iptables last, and only as a fallback: on a modern host the nft backend
	// already reported the same rules above. It matters for a host still on
	// iptables-persistent with no nft binary, which every probe above misses —
	// so a correctly firewalled machine was told it had no firewall at all,
	// and the ports checker simultaneously stopped treating it as shielded.
	if st, which := query("iptables", "iptables", []string{"-S", "INPUT"}, hasDropPolicy); st == StatusActive {
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

// hasDropPolicy reports whether `iptables -S INPUT` shows a default-deny
// INPUT policy. Only the chain policy counts: individual ACCEPT rules say
// nothing about what happens to traffic that matches none of them, and a
// policy of ACCEPT means everything not explicitly dropped gets through.
func hasDropPolicy(out string) bool {
	for _, line := range strings.Split(strings.ToLower(out), "\n") {
		switch strings.TrimSpace(line) {
		case "-p input drop", "-p input reject":
			return true
		}
	}
	return false
}

// ProbedTools names every binary probe consults. It is exported because the
// ports and agent checkers both call Probe, and their tests need to build a
// host with no firewall at all. Hardcoding the list in each of those packages
// meant that adding a probe here silently turned their "no firewall" fixtures
// into "firewall state unreadable", changing what they asserted without
// changing what they said.
var ProbedTools = []string{"ufw", "firewall-cmd", "nft", "iptables"}

func availableTools(r platform.CommandRunner) []string {
	var tools []string
	for _, t := range ProbedTools {
		if platform.Has(r, t) {
			tools = append(tools, t)
		}
	}
	if len(tools) == 0 {
		return []string{"none installed"}
	}
	return tools
}
