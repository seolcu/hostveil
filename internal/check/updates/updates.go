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
	"time"

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
	// PAMModulePaths are the distro locations checked for pam_pwquality.
	// Overridable so tests never depend on packages installed on the runner.
	PAMModulePaths []string
	PAMTmpdirPaths []string
	// SysstatConfigPath controls collection after the package is installed.
	SysstatConfigPath string
	// DnfAutomaticDefaults and DnfAutomaticConfig are where dnf-automatic
	// reads apply_updates: dnf5 loads the first and then the second over it,
	// dnf4 has only the second. Overridable for tests.
	DnfAutomaticDefaults string
	DnfAutomaticConfig   string
	// OSReleasePath is where VERSION_CODENAME is read for unattended-
	// upgrades' ${distro_codename}; overridable for tests.
	OSReleasePath string
}

func (c *Checker) osReleasePath() string {
	if c.OSReleasePath != "" {
		return c.OSReleasePath
	}
	return "/etc/os-release"
}

// New returns an updates checker.
func New() *Checker {
	return &Checker{
		AptConfigPath:      "/etc/apt/apt.conf.d/20auto-upgrades",
		RebootRequiredPath: "/var/run/reboot-required",
		PAMModulePaths: []string{
			"/usr/lib/x86_64-linux-gnu/security/pam_pwquality.so",
			"/usr/lib/aarch64-linux-gnu/security/pam_pwquality.so",
			"/usr/lib/security/pam_pwquality.so",
		},
		PAMTmpdirPaths: []string{
			"/usr/lib/x86_64-linux-gnu/security/pam_tmpdir.so",
			"/usr/lib/aarch64-linux-gnu/security/pam_tmpdir.so",
			"/usr/lib/security/pam_tmpdir.so",
		},
		SysstatConfigPath:    "/etc/default/sysstat",
		DnfAutomaticDefaults: "/usr/share/dnf5/dnf5-plugins/automatic.conf",
		DnfAutomaticConfig:   "/etc/dnf/automatic.conf",
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
		// *is*, and therefore whether Hostveil can do it unattended. Ubuntu
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

	// These tools provide independent host accounting, integrity, password
	// quality, and malware coverage. Installation changes the package database
	// and may start a service, so every remediation is Review despite being
	// mechanically well-defined.
	tools := []struct {
		id, title, description, command, pkg string
		severity                             model.Severity
	}{
		{"updates.process-accounting", "Process accounting is not installed", "Process accounting records commands after they exit, preserving an audit trail that ordinary process listings cannot reconstruct.", "lastcomm", "acct", model.SeverityLow},
		{"updates.sysstat", "System activity accounting is not installed", "sysstat keeps historical CPU, memory, disk, and network activity that helps distinguish compromise from ordinary load after an incident.", "sar", "sysstat", model.SeverityLow},
		{"updates.auditd", "The Linux audit daemon is not installed", "auditd records security-relevant kernel events under an explicit policy and preserves evidence that application logs do not contain.", "auditctl", "auditd", model.SeverityMedium},
		{"updates.debsums", "Installed package files cannot be verified", "debsums compares installed files with package checksums, exposing modified system binaries and damaged installations.", "debsums", "debsums", model.SeverityLow},
		{"updates.rkhunter", "No rootkit scanner is installed", "A second-opinion rootkit scanner checks the host for known persistence artifacts and suspicious system-file changes.", "rkhunter", "rkhunter", model.SeverityLow},
		{"updates.apt-show-versions", "Patch inventory tooling is not installed", "apt-show-versions makes installed and available package versions independently visible to patch-management audits.", "apt-show-versions", "apt-show-versions", model.SeverityLow},
		{"updates.apt-listchanges", "APT changelog review is not installed", "apt-listchanges surfaces important package changes before upgrades are committed.", "apt-listchanges", "apt-listchanges", model.SeverityLow},
		{"updates.fail2ban", "Repeated authentication failures are not automatically blocked", "fail2ban can temporarily block sources that repeatedly fail authentication, reducing online guessing attempts.", "fail2ban-client", "fail2ban", model.SeverityMedium},
	}
	if c.SysstatConfigPath != "" && platform.Has(env.Runner, "sar") {
		if data, err := os.ReadFile(c.SysstatConfigPath); err == nil && !strings.Contains(string(data), `ENABLED="true"`) {
			findings = append(findings, model.NewFinding("updates.sysstat-disabled", "System activity collection is disabled", model.SeverityLow, model.SourceUpdates, model.RemediationAuto,
				model.WithDescription("sysstat is installed, but its periodic collector is disabled, so no historical activity exists when an incident needs investigation."),
				model.WithHowToFix("Set ENABLED=\"true\" in "+c.SysstatConfigPath+"."), model.WithEvidence("config", c.SysstatConfigPath)))
		}
	}
	for _, tool := range tools {
		if platform.Has(env.Runner, tool.command) {
			continue
		}
		findings = append(findings, packageFinding(tool.id, tool.title, tool.description, tool.pkg, tool.severity))
	}
	if len(c.PAMModulePaths) > 0 {
		pamFound := false
		for _, path := range c.PAMModulePaths {
			if _, err := os.Stat(path); err == nil {
				pamFound = true
				break
			}
		}
		if !pamFound {
			findings = append(findings, packageFinding("updates.pam-pwquality", "PAM has no password-quality module", "pam_pwquality rejects weak new passwords before they become reusable credentials on this host.", "libpam-pwquality", model.SeverityMedium))
		}
	}
	if len(c.PAMTmpdirPaths) > 0 {
		found := false
		for _, path := range c.PAMTmpdirPaths {
			if _, err := os.Stat(path); err == nil {
				found = true
				break
			}
		}
		if !found {
			findings = append(findings, packageFinding("updates.pam-tmpdir", "PAM sessions share global temporary directories", "pam_tmpdir gives each authenticated user private temporary directories instead of sharing predictable names in /tmp.", "libpam-tmpdir", model.SeverityLow))
		}
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
	questions := 2
	out, err := env.Runner.Run(ctx, "apt", "list", "--upgradable")
	if err != nil {
		reasons = append(reasons, "cannot list pending updates")
	} else {
		if n := countAptSecurityUpdates(string(out)); n > 0 {
			findings = append(findings, pendingFinding(n, "apt", "sudo apt update && sudo apt dist-upgrade"))
		}
		// A third question once the mechanism is on and something is
		// waiting: will it ever install what is waiting? See aptexcluded.go.
		if ok && enabled {
			questions++
			groups, gerr := excludedOrigins(ctx, env.Runner, string(out), env.DistroID, osReleaseCodename(c.osReleasePath()))
			switch {
			case gerr != nil:
				reasons = append(reasons, gerr.Error())
			case len(groups) > 0:
				findings = append(findings, excludedFinding(groups))
			}
		}
	}

	// Whether automatic updates are configured, and whether anything is
	// waiting — and, when both hold, whether it will ever be installed. Every
	// gap is reported, rather than the first standing for the domain.
	if len(reasons) > 0 {
		return findings, &check.PartialError{
			Reason:  strings.Join(reasons, "; "),
			Covered: questions - len(reasons),
			Total:   questions,
		}
	}
	return findings, nil
}

func packageFinding(id, title, description, pkg string, severity model.Severity) model.Finding {
	return model.NewFinding(id, title, severity, model.SourceUpdates, model.RemediationReview,
		model.WithDescription(description),
		model.WithHowToFix("Install the `"+pkg+"` package after reviewing its services and disk use."),
		model.WithEvidence("package-manager", "apt"), model.WithEvidence("package", pkg))
}

// dnfTimeout bounds the dnf probes, which may download repository metadata.
const dnfTimeout = 5 * time.Minute

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
	//
	// UnitFileState rather than `systemctl is-enabled`: on dnf5 (Fedora 41
	// and later) dnf-automatic.timer is an alias of dnf5-automatic.timer, and
	// is-enabled answers "alias" for it whether the timer is on or not. So the
	// finding outlived its own fix on every such host — found on a real
	// Fedora 44 by scripts/e2e/vm.sh. show resolves the alias first.
	state, err := env.Runner.Run(ctx, "systemctl", "show", "dnf-automatic.timer", "--property=LoadState,UnitFileState")
	props := systemdProps(string(state))
	switch {
	case err != nil && !platform.Has(env.Runner, "systemctl"):
		reasons = append(reasons, "cannot tell whether dnf-automatic is enabled — systemctl is not available")
	case err != nil:
		reasons = append(reasons, "cannot tell whether dnf-automatic is enabled — systemctl did not answer")
	case props["LoadState"] != "loaded":
		// systemd answered and does not have the unit: it is not installed.
		f := disabledFinding("dnf-automatic",
			"Install and enable dnf-automatic: `dnf install dnf-automatic`, set `apply_updates = yes` under [commands] in "+
				c.DnfAutomaticConfig+", then `systemctl enable --now dnf-automatic.timer`.")
		f.Evidence["installed"] = "false"
		f.Evidence["config"] = c.DnfAutomaticConfig
		findings = append(findings, f)
	default:
		// A timer that runs is only half of it. dnf-automatic's shipped
		// default is apply_updates = no — it downloads updates and installs
		// none — so an enabled timer on a stock config is a host that
		// believes it patches itself and does not.
		apply, ok := c.dnfApplyUpdates()
		timerOn := props["UnitFileState"] == "enabled"
		switch {
		case !ok:
			reasons = append(reasons, "cannot tell whether dnf-automatic installs updates — "+c.DnfAutomaticConfig+" could not be read")
		case !timerOn || !apply:
			f := disabledFinding("dnf-automatic", dnfAutomaticHowToFix(c.DnfAutomaticConfig, timerOn, apply))
			f.Evidence["installed"] = "true"
			f.Evidence["config"] = c.DnfAutomaticConfig
			f.Evidence["timer"] = map[bool]string{true: "enabled", false: "disabled"}[timerOn]
			f.Evidence["apply_updates"] = map[bool]string{true: "yes", false: "no"}[apply]
			if timerOn {
				// The whole remediation is one key in one file, reversible
				// from a checkpoint: the same shape, and the same kind, as
				// apt's periodic keys.
				f.Remediation = model.RemediationAuto
			}
			findings = append(findings, f)
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
	//
	// dnf5 has no needs-restarting binary; it is a dnf subcommand there, and
	// asking only for the binary left this question unanswered on every
	// Fedora 41 and later. dnf4 hosts with dnf-plugins-core answer it too.
	//
	// Both dnf probes refresh repository metadata when it has expired, which
	// on a fresh Fedora 44 took over a minute — past platform.DefaultTimeout,
	// so whichever probe ran first was killed and its question went
	// unanswered. They get a deadline of their own, as Trivy does.
	dnfCtx, cancel := context.WithTimeout(ctx, dnfTimeout)
	defer cancel()
	var rebootOut []byte
	if platform.Has(env.Runner, "needs-restarting") {
		rebootOut, _ = env.Runner.Run(dnfCtx, "needs-restarting", "-r")
	} else {
		rebootOut, _ = env.Runner.Run(dnfCtx, "dnf", "needs-restarting", "-r")
	}
	switch classifyNeedsRestarting(string(rebootOut)) {
	case rebootRequired:
		findings = append(findings, rebootFinding("sudo reboot"))
	case rebootUnknown:
		if platform.Has(env.Runner, "needs-restarting") {
			reasons = append(reasons, "cannot tell whether a reboot is pending")
		} else {
			reasons = append(reasons, "cannot tell whether a reboot is pending — neither needs-restarting nor `dnf needs-restarting` answered (`dnf install dnf-utils`)")
		}
	}

	// `--security`, not the positional `security`. dnf4 read the bare word as
	// a filter; dnf5 reads it as the name of an advisory, finds none called
	// that, exits 0 and lists nothing. A real Fedora 44 with eighty pending
	// security packages, openssl among them, was reported as fully patched.
	secOut, err := env.Runner.Run(dnfCtx, "dnf", "-q", "updateinfo", "list", "--security")
	switch {
	case err != nil:
		reasons = append(reasons, "cannot list pending security updates")
	default:
		if n := countDnfSecurityAdvisories(string(secOut)); n > 0 {
			findings = append(findings, pendingFinding(n, "dnf", "sudo dnf upgrade --security"))
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

// countDnfSecurityAdvisories counts rows in `dnf updateinfo list --security`,
// one per package. dnf4 prints "ADVISORY SEVERITY/Sec. package"; dnf5 prints
// a header and then "ADVISORY security SEVERITY package ISSUED". A row is
// counted only when its type column says security, so the header and
// whatever else dnf prints around the table are not.
func countDnfSecurityAdvisories(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "security" || strings.HasSuffix(fields[1], "/Sec.") {
			n++
		}
	}
	return n
}

// systemdProps reads `systemctl show --property=...` output into a map.
// systemd prints properties in its own order, not the order asked for.
func systemdProps(out string) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	return props
}

// dnfApplyUpdates reports whether dnf-automatic will install what it
// downloads: [commands] apply_updates, read from the shipped defaults and
// then the host's overrides, as dnf5 layers them. Absent everywhere means
// no, which is the default both dnf versions ship. ok is false when a file
// exists and cannot be read.
func (c *Checker) dnfApplyUpdates() (apply, ok bool) {
	for _, p := range []string{c.DnfAutomaticDefaults, c.DnfAutomaticConfig} {
		data, err := os.ReadFile(p) //nolint:gosec // G304: fixed system path, overridable only by tests
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, false
		}
		if v, set := iniValue(string(data), "commands", "apply_updates"); set {
			apply = parseDnfBool(v)
		}
	}
	return apply, true
}

// iniValue returns the last value of key in section, the way libdnf's
// parser resolves a repeated key.
func iniValue(text, section, key string) (value string, set bool) {
	current := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if current != section {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			value, set = strings.TrimSpace(v), true
		}
	}
	return value, set
}

func parseDnfBool(v string) bool {
	switch strings.ToLower(v) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

func dnfAutomaticHowToFix(config string, timerOn, apply bool) string {
	switch {
	case !apply && timerOn:
		return "dnf-automatic runs but only downloads updates — its default is `apply_updates = no`. " +
			"Set `apply_updates = yes` under [commands] in " + config + "."
	case !apply:
		return "Set `apply_updates = yes` under [commands] in " + config +
			", then `systemctl enable --now dnf-automatic.timer` — the default only downloads updates."
	default:
		return "Enable it: `systemctl enable --now dnf-automatic.timer`."
	}
}

// rebootFinding reports that patches are installed but not in force. The
// machine is still executing the vulnerable code it already downloaded the
// fix for, which is a strictly worse position than not having patched: the
// operator believes the work is done.
func rebootFinding(howToFix string) model.Finding {
	return model.NewFinding("updates.reboot-required", "A reboot is needed for installed security updates to take effect",
		model.SeverityHigh, model.SourceUpdates, model.RemediationReview,
		model.WithDescription("Updates to the kernel or a core library have been installed, but the running system is still using the old code held in memory. Until this host restarts, it stays vulnerable to exactly the issues those patches fixed — and because the packages already show as up to date, it is easy to believe the work is finished."),
		model.WithHowToFix("Restart the host when you can take the downtime: `"+howToFix+"`. Check what will restart with it first if you run services without a restart policy."),
		model.WithEvidence("mechanism", "reboot flag"),
	)
}

// pendingFinding reports security updates that are available and not applied.
// Severity scales with the count: a couple of pending patches is routine drift,
// dozens means automatic updates are not actually working.
func pendingFinding(n int, mechanism, howToFix string) model.Finding {
	sev := model.SeverityMedium
	if n >= 10 {
		sev = model.SeverityHigh
	}
	return model.NewFinding("updates.pending-security", fmt.Sprintf("%d security update(s) are available but not installed", n),
		sev, model.SourceUpdates, model.RemediationReview,
		model.WithDescription("These packages have published security fixes that this host has not applied. Every one is a publicly documented vulnerability with a patch already written, which is the category attackers scan for first. A large backlog usually means automatic updates are configured but failing rather than simply switched off."),
		model.WithHowToFix("Apply them: `"+howToFix+"`. If automatic updates are enabled and this backlog keeps growing, check `systemctl status unattended-upgrades` or the dnf-automatic timer for errors."),
		model.WithEvidence("pending", strconv.Itoa(n)), model.WithEvidence("package-manager", mechanism),
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
