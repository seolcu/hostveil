// Package updates implements a native checker for automatic security
// updates. It verifies that the host is set up to apply security patches
// on its own (unattended-upgrades on apt systems, dnf-automatic on dnf
// systems) rather than relying on the operator to remember.
package updates

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports whether automatic security updates are enabled.
type Checker struct {
	// AptConfigPath is the apt periodic-upgrade config; overridable for tests.
	AptConfigPath string
	// RebootRequiredPath is the flag file apt's packages touch when a
	// installed update needs a reboot to take effect; overridable for tests.
	RebootRequiredPath string
}

// New returns an updates checker.
func New() *Checker {
	return &Checker{
		AptConfigPath:      "/etc/apt/apt.conf.d/20auto-upgrades",
		RebootRequiredPath: "/var/run/reboot-required",
	}
}

// Source identifies the updates domain.
func (*Checker) Source() model.Source { return model.SourceUpdates }

// Available requires a package manager whose auto-update mechanism this
// checker knows how to verify. Anywhere else it reports a skip rather than
// running: apk and pacman have no standard unattended-upgrade daemon to
// look for, so "found nothing" would be indistinguishable from "did not
// look" — and the two score identically while meaning opposite things.
// A skip excludes the axis as N/A instead of awarding it full marks.
func (*Checker) Available(_ context.Context, env platform.Env) (bool, string) {
	switch env.PackageManager {
	case platform.PMApt, platform.PMDnf:
		return true, ""
	case platform.PMUnknown:
		return false, "no recognized package manager — cannot verify automatic updates"
	default:
		return false, "automatic-update checks cover apt and dnf hosts only — detected " + string(env.PackageManager)
	}
}

// Check reports on both halves of staying patched: that the mechanism is
// enabled, and that it has actually caught up.
//
// Having unattended-upgrades enabled was previously the whole test, which
// meant a host with sixty pending security patches and a kernel update
// installed but never rebooted scored the axis full marks. The mechanism
// being switched on says nothing about whether the machine is currently
// running patched code, and that is the thing an operator cares about.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	switch env.PackageManager {
	case platform.PMApt:
		return c.auditApt(ctx, env)
	case platform.PMDnf:
		return c.auditDnf(ctx, env)
	default:
		return nil, fmt.Errorf("unsupported package manager %q: Available should have skipped this checker", env.PackageManager)
	}
}

func (c *Checker) auditApt(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	var findings []model.Finding
	if !aptUnattendedEnabled(c.AptConfigPath) {
		findings = append(findings, disabledFinding("unattended-upgrades",
			"Install and enable unattended-upgrades: `apt install unattended-upgrades` then `dpkg-reconfigure -plow unattended-upgrades`."))
	}
	// apt's packages create this file from their postinst when an installed
	// update cannot take effect until the machine restarts — a new kernel,
	// glibc, or libssl. Absence is a definite answer, not a guess.
	if _, err := os.Stat(c.RebootRequiredPath); err == nil {
		findings = append(findings, rebootFinding("sudo reboot"))
	}

	out, err := env.Runner.Run(ctx, "apt", "list", "--upgradable")
	if err != nil {
		return findings, &check.PartialError{
			Reason: "cannot list pending updates — checked that automatic updates are configured, but not whether they have caught up",
		}
	}
	if n := countAptSecurityUpdates(string(out)); n > 0 {
		findings = append(findings, pendingFinding(n, "sudo apt update && sudo apt upgrade"))
	}
	return findings, nil
}

func (c *Checker) auditDnf(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	var findings []model.Finding
	out, err := env.Runner.Run(ctx, "systemctl", "is-enabled", "dnf-automatic.timer")
	if err != nil || strings.TrimSpace(string(out)) != "enabled" {
		findings = append(findings, disabledFinding("dnf-automatic",
			"Install and enable dnf-automatic: `dnf install dnf-automatic` then `systemctl enable --now dnf-automatic.timer` (configure it to apply security updates)."))
	}

	// `needs-restarting -r` exits non-zero precisely when a reboot IS
	// required, so the exit status cannot be read as success or failure here.
	// Its stdout is unambiguous and is still captured on a non-zero exit, so
	// the text is the signal — and a reply matching neither phrase means the
	// command did not answer, which must not be read as "no reboot needed".
	rebootOut, _ := env.Runner.Run(ctx, "needs-restarting", "-r")
	switch reboot := classifyNeedsRestarting(string(rebootOut)); reboot {
	case rebootRequired:
		findings = append(findings, rebootFinding("sudo reboot"))
	case rebootUnknown:
		return findings, &check.PartialError{
			Reason: "cannot tell whether a reboot is pending — checked that automatic updates are configured, but not whether they have taken effect",
		}
	}

	secOut, err := env.Runner.Run(ctx, "dnf", "-q", "updateinfo", "list", "security")
	if err != nil {
		return findings, &check.PartialError{
			Reason: "cannot list pending security updates — checked that automatic updates are configured, but not whether they have caught up",
		}
	}
	if n := countDnfSecurityAdvisories(string(secOut)); n > 0 {
		findings = append(findings, pendingFinding(n, "sudo dnf upgrade --security"))
	}
	return findings, nil
}

// aptUnattendedEnabled reports whether the apt periodic config enables
// unattended upgrades.
func aptUnattendedEnabled(path string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // fixed system path
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//") || line == "" {
			continue
		}
		if strings.Contains(line, "Unattended-Upgrade") && strings.Contains(line, `"1"`) {
			return true
		}
	}
	return false
}

// rebootState is what `needs-restarting -r` told us, including the case
// where it told us nothing usable.
type rebootState int

const (
	rebootNotNeeded rebootState = iota
	rebootRequired
	rebootUnknown
)

// classifyNeedsRestarting reads dnf's answer from its text rather than its
// exit status, which is inverted: it exits non-zero when a reboot IS needed.
func classifyNeedsRestarting(out string) rebootState {
	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "reboot is required"),
		strings.Contains(lower, "reboot is probably required"):
		return rebootRequired
	case strings.Contains(lower, "reboot should not be necessary"):
		return rebootNotNeeded
	default:
		return rebootUnknown
	}
}

// countAptSecurityUpdates counts upgradable packages coming from a security
// suite. apt names it in the origin field, e.g.
//
//	libssl3/jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: ...]
//
// Only security updates are counted. A host deliberately pinned behind on
// feature updates is a maintenance choice; one behind on security patches is
// running known-exploitable code.
func countAptSecurityUpdates(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// The first line is "Listing..." and unrelated lines lack a slash.
		name, rest, ok := strings.Cut(line, "/")
		if !ok || name == "" || !strings.Contains(rest, "upgradable from:") {
			continue
		}
		suite, _, _ := strings.Cut(rest, " ")
		if strings.Contains(suite, "-security") {
			n++
		}
	}
	return n
}

// countDnfSecurityAdvisories counts advisory rows in `dnf updateinfo list
// security`. Each row is "ADVISORY SEVERITY package", and dnf prints
// "Last metadata expiration check" and blank lines around them.
func countDnfSecurityAdvisories(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last metadata") {
			continue
		}
		if len(strings.Fields(line)) >= 3 {
			n++
		}
	}
	return n
}

// rebootFinding reports that patches are installed but not in force. The
// machine is still executing the vulnerable code it already downloaded the
// fix for, which is a strictly worse position than not having patched: the
// operator believes the work is done.
func rebootFinding(howToFix string) model.Finding {
	return model.NewFinding("updates.reboot-required", "A reboot is needed for installed security updates to take effect",
		model.SeverityHigh, model.SourceUpdates, model.RemediationManual,
		model.WithDescription("Updates to the kernel or a core library have been installed, but the running system is still using the old code held in memory. Until this host restarts, it stays vulnerable to exactly the issues those patches fixed — and because the packages already show as up to date, it is easy to believe the work is finished."),
		model.WithHowToFix("Restart the host when you can take the downtime: `"+howToFix+"`. Check what will restart with it first if you run services without a restart policy."),
		model.WithEvidence("mechanism", "reboot flag"),
	)
}

// pendingFinding reports security updates that are available and not applied.
// Severity scales with the count: a couple of pending patches is routine drift,
// dozens means automatic updates are not actually working.
func pendingFinding(n int, howToFix string) model.Finding {
	sev := model.SeverityMedium
	if n >= 10 {
		sev = model.SeverityHigh
	}
	return model.NewFinding("updates.pending-security", fmt.Sprintf("%d security update(s) are available but not installed", n),
		sev, model.SourceUpdates, model.RemediationManual,
		model.WithDescription("These packages have published security fixes that this host has not applied. Every one is a publicly documented vulnerability with a patch already written, which is the category attackers scan for first. A large backlog usually means automatic updates are configured but failing rather than simply switched off."),
		model.WithHowToFix("Apply them: `"+howToFix+"`. If automatic updates are enabled and this backlog keeps growing, check `systemctl status unattended-upgrades` or the dnf-automatic timer for errors."),
		model.WithEvidence("pending", strconv.Itoa(n)),
	)
}

func disabledFinding(mechanism, howToFix string) model.Finding {
	return model.NewFinding("updates.disabled", "Automatic security updates are not enabled",
		model.SeverityMedium, model.SourceUpdates, model.RemediationReview,
		model.WithDescription("Without automatic security updates, known vulnerabilities in your OS and its packages stay unpatched until you manually update. Most self-hosters forget, leaving public services exploitable for months."),
		model.WithHowToFix(howToFix),
		model.WithEvidence("mechanism", mechanism),
	)
}
