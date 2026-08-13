// Package updates implements a native checker for automatic security
// updates. It verifies that the host is set up to apply security patches
// on its own (unattended-upgrades on apt systems, dnf-automatic on dnf
// systems) rather than relying on the operator to remember.
package updates

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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
	// AptConfDirPath is the directory apt reads fragments from; overridable
	// for tests.
	AptConfDirPath string
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
	var reasons []string
	// apt reads every fragment in apt.conf.d and the last assignment wins, so
	// the question is what apt resolves the option to — not what one file
	// says. Reading 20auto-upgrades alone reported "disabled" as "enabled" on
	// any host carrying 99-disable-auto-upgrades, which cloud images and
	// several hardening guides ship, and the fix then wrote into the file
	// that loses. See aptorigin.go.
	enabled, ok := c.aptEnabled(ctx, env)
	switch {
	case !ok:
		reasons = append(reasons, "cannot tell whether unattended upgrades are enabled: neither `apt-config dump "+
			periodicKey+"` nor "+c.AptConfigPath+" could be read")
	case !enabled:
		// Whether the package is already here decides what the remediation
		// *is*, and therefore whether hostveil can do it unattended. Ubuntu
		// ships unattended-upgrades installed and Debian's netinst offers it,
		// so the common case is a host where the whole fix is writing one
		// config file — reversible, and Auto. Where the package is missing the
		// fix has to install it, which is a command with no checkpoint.
		f := disabledFinding("unattended-upgrades",
			"Install and enable unattended-upgrades: `apt install unattended-upgrades` then `dpkg-reconfigure -plow unattended-upgrades`.")
		if platform.Has(env.Runner, "unattended-upgrade") {
			f.Evidence["installed"] = "true"
			f.Evidence["config"] = c.AptConfigPath
			// The file whose assignment apt reads last, when one exists.
			// Writing into 20auto-upgrades while a later fragment sets the
			// same option to "0" is a fix apt never sees. Same shape, and the
			// same evidence key, as the sysctl domain's winner.
			if origin := aptOrigin(c.AptConfDir()); origin != "" {
				f.Evidence["set-by"] = origin
				f.Evidence["config"] = origin
			}
			f.HowToFix = "unattended-upgrades is installed but switched off. Set both periodic keys in " +
				c.AptConfigPath + ": `APT::Periodic::Update-Package-Lists \"1\";` and " +
				"`APT::Periodic::Unattended-Upgrade \"1\";`."
			f.Remediation = model.RemediationAuto
		}
		findings = append(findings, f)
	}
	// apt's packages create this file from their postinst when an installed
	// update cannot take effect until the machine restarts — a new kernel,
	// glibc, or libssl. Absence is a definite answer, not a guess.
	if _, err := os.Stat(c.RebootRequiredPath); err == nil {
		findings = append(findings, rebootFinding("sudo reboot"))
	}

	// `apt`, not `apt-get`, despite apt printing that its CLI is not a stable
	// scripting interface.
	//
	// The stable alternative is `apt-get --just-print upgrade`, and it answers
	// a different question: it lists what `upgrade` would actually install,
	// which excludes anything held back for needing new or removed packages.
	// Security updates land in that category regularly. Counting from it
	// would report fewer pending security updates than the host really has —
	// erring toward "you are patched" on a machine that is not, which is the
	// one direction this checker must never be wrong in.
	//
	// The warning apt prints goes to stderr, and Run captures stdout only, so
	// it cannot reach countAptSecurityUpdates.
	out, err := env.Runner.Run(ctx, "apt", "list", "--upgradable")
	if err != nil {
		reasons = append(reasons, "cannot list pending updates")
	} else if n := countAptSecurityUpdates(string(out)); n > 0 {
		findings = append(findings, pendingFinding(n, "sudo apt update && sudo apt upgrade"))
	}

	// Two questions here, as on the dnf side: whether automatic updates are
	// configured, and whether anything is waiting. Both are reported when
	// both go unanswered, rather than the first gap standing for the domain.
	if len(reasons) > 0 {
		return findings, &check.PartialError{
			Reason:  strings.Join(reasons, "; "),
			Covered: 2 - len(reasons),
			Total:   2,
		}
	}
	return findings, nil
}

func (c *Checker) auditDnf(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	var findings []model.Finding
	var reasons []string

	// `systemctl is-enabled` exits non-zero for "disabled" and for "there is
	// no systemctl here" alike, and reading the second as the first turns "I
	// could not look" into the positive claim that automatic updates are off
	// — on a host where nothing was consulted.
	//
	// So the unit is asked whether it exists first, the way the systemd
	// domain does it: LoadState answers `loaded` only for a unit systemd
	// actually read, and a command that cannot run at all answers nothing.
	// A unit that is genuinely absent *is* the finding — dnf-automatic is
	// not installed — and that is the one case where a non-zero exit is an
	// answer rather than a silence.
	state, err := env.Runner.Run(ctx, "systemctl", "show", "dnf-automatic.timer", "--property=LoadState")
	switch {
	case err != nil && !platform.Has(env.Runner, "systemctl"):
		reasons = append(reasons, "cannot tell whether dnf-automatic is enabled — systemctl is not available")
	case err != nil:
		reasons = append(reasons, "cannot tell whether dnf-automatic is enabled — systemctl did not answer")
	case !strings.Contains(string(state), "LoadState=loaded"):
		// systemd answered and does not have the unit: it is not installed.
		findings = append(findings, disabledFinding("dnf-automatic",
			"Install and enable dnf-automatic: `dnf install dnf-automatic` then `systemctl enable --now dnf-automatic.timer` (configure it to apply security updates)."))
	default:
		out, err := env.Runner.Run(ctx, "systemctl", "is-enabled", "dnf-automatic.timer")
		// The unit is loaded, so a non-zero exit here means disabled, static
		// or masked — every one of which is "not enabled" and none of which
		// is silence.
		if err != nil || strings.TrimSpace(string(out)) != "enabled" {
			findings = append(findings, disabledFinding("dnf-automatic",
				"Enable it: `systemctl enable --now dnf-automatic.timer` (and configure it to apply security updates)."))
		}
	}

	// Reasons accumulate rather than returning at the first one. Both probes
	// below are independent questions about this domain, and answering only
	// the first used to mean the second was never asked: on a stock minimal
	// Fedora or Rocky there is no needs-restarting (it ships in dnf-utils),
	// so the reboot check came back unknown, the function returned, and
	// pending security updates went uncounted on every such host — while the
	// domain reported only that a reboot could not be determined.

	// `needs-restarting -r` exits non-zero precisely when a reboot IS
	// required, so the exit status cannot be read as success or failure here.
	// Its stdout is unambiguous and is still captured on a non-zero exit, so
	// the text is the signal — and a reply matching neither phrase means the
	// command did not answer, which must not be read as "no reboot needed".
	switch {
	case !platform.Has(env.Runner, "needs-restarting"):
		reasons = append(reasons, "cannot tell whether a reboot is pending — needs-restarting is not installed (`dnf install dnf-utils`)")
	default:
		rebootOut, _ := env.Runner.Run(ctx, "needs-restarting", "-r")
		switch classifyNeedsRestarting(string(rebootOut)) {
		case rebootRequired:
			findings = append(findings, rebootFinding("sudo reboot"))
		case rebootUnknown:
			reasons = append(reasons, "cannot tell whether a reboot is pending")
		}
	}

	secOut, err := env.Runner.Run(ctx, "dnf", "-q", "updateinfo", "list", "security")
	switch {
	case err != nil:
		reasons = append(reasons, "cannot list pending security updates")
	default:
		if n := countDnfSecurityAdvisories(string(secOut)); n > 0 {
			findings = append(findings, pendingFinding(n, "sudo dnf upgrade --security"))
		}
	}

	if len(reasons) > 0 {
		return findings, &check.PartialError{
			Reason: strings.Join(reasons, "; ") +
				" — checked that automatic updates are configured, but not whether they have caught up",
			Covered: 3 - len(reasons),
			Total:   3,
		}
	}
	return findings, nil
}

// aptUnattendedEnabled reports whether the apt periodic config enables
// unattended upgrades.
// The bool answers "enabled"; ok answers whether the file could be consulted
// at all. An absent config is a real answer — nothing has configured
// unattended upgrades, which is exactly the finding — but an unreadable one is
// not, and reading a permission error as "disabled" is the same silence this
// domain's systemctl probe used to produce.
func aptUnattendedEnabled(path string) (enabled, ok bool) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: fixed system path
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, true
	case err != nil:
		return false, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//") || line == "" {
			continue
		}
		if strings.Contains(line, "Unattended-Upgrade") && strings.Contains(line, `"1"`) {
			return true, true
		}
	}
	return false, true
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

// AptConfDir is the directory apt reads its fragments from, overridable for
// tests alongside AptConfigPath.
func (c *Checker) AptConfDir() string {
	if c.AptConfDirPath != "" {
		return c.AptConfDirPath
	}
	return aptConfDir
}

// aptEnabled reports whether unattended upgrades are in force, asking apt
// first and falling back to the conventional file only where apt cannot be
// asked. The second return is whether the question could be answered at all.
func (c *Checker) aptEnabled(ctx context.Context, env platform.Env) (enabled, ok bool) {
	if value, set, asked := aptEffective(ctx, env.Runner); asked {
		// apt answered. An unset option is a definite "not enabled" — that is
		// exactly the finding — and any value other than "0" enables it.
		return set && value != "0", true
	}
	return aptUnattendedEnabled(c.AptConfigPath)
}
