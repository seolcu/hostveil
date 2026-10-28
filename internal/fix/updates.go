package fix

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// registerUpdates wires the auto-update fix into the registry.
func registerUpdates(r *Registry) {
	r.Register("updates.disabled", buildEnableAutoUpdates)
	r.Register("updates.pending-security", buildApplySecurityUpdates)
	for _, id := range []string{
		"updates.process-accounting", "updates.sysstat", "updates.auditd",
		"updates.debsums", "updates.rkhunter", "updates.pam-pwquality",
		"updates.apt-show-versions",
		"updates.apt-listchanges", "updates.pam-tmpdir", "updates.fail2ban",
	} {
		r.Register(id, buildInstallHardeningPackage)
	}
	r.Register("updates.sysstat-disabled", buildEnableSysstat)
	r.Register("updates.origin-excluded", buildAllowOrigins)
}

// allowOriginsPath is Hostveil's own drop-in for origin patterns. It is a
// file of its own rather than an edit to 50unattended-upgrades, which the
// package owns and replaces on upgrade, and its list is appended to the
// distribution's because apt merges list values across fragments.
const allowOriginsPath = "/etc/apt/apt.conf.d/52hostveil-origins"

// buildAllowOrigins adds the skipped repositories' patterns to
// unattended-upgrades' list. Review, never Auto: letting a third-party
// repository update the host unattended is a decision about trusting that
// repository, and on a host with Automatic-Reboot a kernel from it reboots
// the machine. The edit has a checkpoint, and apt-config checks the result
// parses before it is written.
func buildAllowOrigins(f model.Finding) (Fix, error) {
	var patterns []string
	for _, p := range strings.Split(f.Evidence["patterns"], "\n") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		return Fix{}, fmt.Errorf("finding %s names no repositories; re-scan before fixing", f.ID)
	}
	return Fix{
		FindingID: f.ID,
		Label:     "Let unattended-upgrades install from these repositories",
		Kind:      model.RemediationReview,
		Actions: []Action{{
			Label:           "Add their origin patterns to " + allowOriginsPath,
			Benefit:         "Updates from these repositories install on the same schedule as the distribution's own, instead of waiting for someone to notice them.",
			Warning:         "From then on these repositories update the host unattended, so you are trusting them as much as the distribution. If one ships a kernel and Unattended-Upgrade::Automatic-Reboot is on, its kernel updates will reboot the machine.",
			Kind:            ActionEdit,
			Path:            allowOriginsPath,
			CreateIfMissing: true,
			Transform:       func(in []byte) ([]byte, error) { return addOriginPatterns(in, patterns) },
			VerifyCmd:       []string{"apt-config", "-c", VerifyPathToken, "dump", "Unattended-Upgrade::Origins-Pattern"},
		}},
	}, nil
}

// addOriginPatterns renders the drop-in with every pattern it already lists
// plus the new ones, in a stable order, so applying the same fix twice is
// a no-op and a later finding adds to the file rather than replacing it.
func addOriginPatterns(in []byte, add []string) ([]byte, error) {
	seen := map[string]bool{}
	var all []string
	for _, m := range regexp.MustCompile(`(?m)^\s*"((?:[^"\\]|\\.)*)"\s*;`).FindAllStringSubmatch(string(in), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			all = append(all, m[1])
		}
	}
	for _, p := range add {
		if strings.ContainsAny(p, "\"\n") {
			return nil, fmt.Errorf("origin pattern %q cannot be written into apt's config", p)
		}
		if !seen[p] {
			seen[p] = true
			all = append(all, p)
		}
	}
	var b strings.Builder
	b.WriteString("// Written by Hostveil (updates.origin-excluded): repositories\n")
	b.WriteString("// unattended-upgrades may install from, beyond the distribution's own.\n")
	b.WriteString("Unattended-Upgrade::Origins-Pattern {\n")
	for _, p := range all {
		b.WriteString("    \"" + p + "\";\n")
	}
	b.WriteString("};\n")
	return []byte(b.String()), nil
}

func buildEnableSysstat(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s names no sysstat config", f.ID)
	}
	return Fix{Label: "Enable sysstat activity collection", Kind: model.RemediationAuto, Actions: []Action{{
		Label: "Set ENABLED to true",
		Benefit: "Turns on the data collection the sysstat package already has installed, so historical " +
			"resource data actually starts accumulating instead of the package sitting present but silent.",
		Kind: ActionEdit, Path: path, Transform: func(in []byte) ([]byte, error) {
			re := regexp.MustCompile(`(?m)^ENABLED=.*$`)
			if re.Match(in) {
				return re.ReplaceAll(in, []byte(`ENABLED="true"`)), nil
			}
			return append(bytes.TrimRight(in, "\n"), []byte("\nENABLED=\"true\"\n")...), nil
		}}}}, nil
}

// pendingSecurityWarning is shown before either package manager's upgrade
// runs. Docker is named specifically, not just "the services they belong
// to": a demo-VM rehearsal of this exact fix upgraded the Docker package,
// which restarted the daemon, which took every container with it — and the
// ones with no restart policy (or one written but not yet in force, see
// model.Finding.Pending) stayed down until something ran `docker compose up
// -d` by hand.
const pendingSecurityWarning = "Upgrading packages can restart the services they belong to, including sshd " +
	"and the Docker daemon — and a container whose compose file has no restart policy in force stays down " +
	"until `docker compose up -d` brings it back. A kernel or libc update may also need a reboot to actually " +
	"take effect. There is no rollback checkpoint; undoing this means downgrading the affected packages by hand."

func buildApplySecurityUpdates(f model.Finding) (Fix, error) {
	var built Fix
	const benefit = "Applies whatever security patches are already sitting unapplied right now — closes " +
		"today's already-known gaps rather than waiting for the next automatic run."
	switch f.Evidence["package-manager"] {
	case "apt":
		built = execFix("Apply pending security updates", "Refresh apt metadata and fully upgrade installed packages",
			benefit, pendingSecurityWarning,
			[][]string{{"apt-get", "update"}, {"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "dist-upgrade", "-y"}})
	case "dnf":
		built = execFix("Apply pending security updates", "Upgrade packages covered by security advisories",
			benefit, pendingSecurityWarning,
			[][]string{{"dnf", "upgrade", "-y", "--security"}})
	default:
		return Fix{}, fmt.Errorf("finding %s has no known package manager", f.ID)
	}
	built.Actions[0].Timeout = 20 * time.Minute
	return built, nil
}

// hardeningPackageBenefit names what each package installed by
// buildInstallHardeningPackage actually buys, since one generic builder is
// shared across every package below.
var hardeningPackageBenefit = map[string]string{
	"acct": "Installs a forensic record of every command run on this host after the fact — turns " +
		"\"something happened\" into \"here is exactly what ran and as whom.\"",
	"sysstat": "Installs ongoing resource-usage history, so a crypto-miner, a DoS, or a runaway " +
		"process shows up as a visible anomaly instead of vanishing the moment it stops.",
	"auditd": "Installs a kernel-level audit trail of security-relevant actions — file access, " +
		"privilege changes — that survives a process exiting or an application log being cleared.",
	"debsums": "Lets the operator verify every installed package's files against their original " +
		"checksums on demand — how a tampered binary gets noticed instead of trusted.",
	"rkhunter": "Installs a rootkit and backdoor scanner, giving the host a second opinion on itself " +
		"beyond what its own compromised binaries might report.",
	"pam-pwquality": "Installs the PAM module that lets password-strength rules actually be enforced " +
		"at login time, not only at account creation.",
	"apt-show-versions": "Lets the operator ask, per package, whether a security update is pending " +
		"from a specific origin — the same query Hostveil's own updates domain depends on.",
	"apt-listchanges": "Shows what actually changed before an upgrade lands, so a package upgrade is " +
		"something the operator reads rather than something that just happens to them.",
	"pam-tmpdir": "Gives every login session its own private /tmp, closing the shared-/tmp race and " +
		"symlink-attack class of local privilege escalation.",
	"fail2ban": "Automatically bans an IP after repeated failed logins, cutting off a brute-force " +
		"attempt while it is still in progress rather than after it succeeds.",
}

func buildInstallHardeningPackage(f model.Finding) (Fix, error) {
	if f.Evidence["package-manager"] != "apt" || f.Evidence["package"] == "" {
		return Fix{}, fmt.Errorf("finding %s has no supported package evidence", f.ID)
	}
	pkg := f.Evidence["package"]
	commands := [][]string{{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", pkg}}
	warning := "Installs " + pkg + " and enables its service. There is no rollback checkpoint; undoing this means removing the package by hand."
	switch pkg {
	case "acct":
		commands = append(commands, []string{"systemctl", "enable", "--now", "acct.service"})
	case "sysstat":
		commands = append(commands,
			[]string{"sed", "-i", `s/^ENABLED=.*/ENABLED="true"/`, "/etc/default/sysstat"},
			[]string{"systemctl", "enable", "--now", "sysstat-collect.timer", "sysstat-summary.timer"})
	case "auditd":
		commands = append(commands,
			[]string{"install", "-m", "0600", "/usr/share/doc/auditd/examples/rules/30-pci-dss-v31.rules", "/etc/audit/rules.d/30-hostveil.rules"},
			[]string{"augenrules", "--load"},
			[]string{"systemctl", "enable", "--now", "auditd.service"})
	case "debsums":
		commands = append(commands, []string{"sed", "-i", `s/^CRON_CHECK=.*/CRON_CHECK=weekly/`, "/etc/default/debsums"})
	case "fail2ban":
		// The one package here that can act on this very session: it starts
		// watching auth logs the moment it is enabled, and a ban is exactly
		// the "sever the operator's own access" case Auto exists to rule out.
		warning += " fail2ban starts watching auth logs immediately and can ban an IP after repeated failed " +
			"logins — including the one this session is on."
	}
	built := execFix("Install host-hardening package "+pkg, "Install and enable "+pkg,
		hardeningPackageBenefit[pkg], warning, commands)
	built.Actions[0].Timeout = 20 * time.Minute
	return built, nil
}

// autoUpdatesBenefit is shared by every path buildEnableAutoUpdates can
// take — the edit path and both exec paths all end at the same outcome.
const autoUpdatesBenefit = "Once enabled, security patches for every installed package arrive on " +
	"their own instead of depending on someone remembering to run apt/dnf."

// buildEnableAutoUpdates installs and enables the distro's automatic
// security-update mechanism, chosen from the finding's evidence.
func buildEnableAutoUpdates(f model.Finding) (Fix, error) {
	switch f.Evidence["mechanism"] {
	case "unattended-upgrades":
		// Where the package is already installed the whole remediation is one
		// config file, which is a file edit: reversible from a checkpoint,
		// and therefore something Hostveil can do unattended. That is the
		// common case — Ubuntu ships unattended-upgrades — and it used to be
		// served by the same `apt-get install` the uncommon case needs, which
		// made an exec action out of a two-line edit and put the most ordinary
		// hardening step on this list behind a human.
		if f.Evidence["installed"] == "true" {
			return enableAptPeriodic(f)
		}
		return execFix("Enable automatic security updates (unattended-upgrades)",
			"Install and enable unattended-upgrades",
			autoUpdatesBenefit,
			"Installs unattended-upgrades and enables its service. There is no rollback checkpoint; "+
				"undoing this means removing the package by hand.",
			[][]string{
				{"apt-get", "install", "-y", "unattended-upgrades"},
				{"systemctl", "enable", "--now", "unattended-upgrades.service"},
			}), nil
	case "dnf-automatic":
		return enableDnfAutomatic(f)
	default:
		return Fix{}, fmt.Errorf("finding %s has no known update mechanism", f.ID)
	}
}

// enableDnfAutomatic sets apply_updates in dnf-automatic's host config and
// then, if the checker found the timer off or missing, installs and starts
// it. Installing and enabling were the whole fix once, and on every dnf host
// that produced a timer that downloads updates and installs none: the shipped
// default is apply_updates = no. Found on a real Fedora 44, where letting the
// timer's service run with this key set installed the pending security
// updates and without it installed nothing.
//
// The file is written first and the commands run after it, so the timer's
// first run already reads the new key. On dnf4 a package installed after the
// write keeps this file and leaves its own beside it as .rpmnew, which is the
// %config(noreplace) contract, and dnf4 defaults every key the file omits.
func enableDnfAutomatic(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s does not name dnf-automatic's config; re-scan before fixing", f.ID)
	}
	act := Action{
		Label:           "Turn on apply_updates in dnf-automatic's config",
		Benefit:         autoUpdatesBenefit,
		Kind:            ActionEdit,
		Path:            path,
		CreateIfMissing: true,
		Transform:       setDnfApplyUpdates,
	}
	if f.Evidence["timer"] == "enabled" {
		return Fix{FindingID: f.ID, Label: "Make dnf-automatic install the updates it downloads",
			Kind: model.RemediationAuto, Actions: []Action{act}}, nil
	}
	if f.Evidence["installed"] != "true" {
		act.AfterWrite = append(act.AfterWrite, []string{"dnf", "install", "-y", "dnf-automatic"})
		act.Label += ", install dnf-automatic"
	}
	act.AfterWrite = append(act.AfterWrite, []string{"systemctl", "enable", "--now", "dnf-automatic.timer"})
	act.Label += " and enable its timer"
	// A rollback restores the config and stops the timer it started. The
	// package stays: removing one is not a rollback anybody asked for.
	act.AfterRestore = [][]string{{"systemctl", "disable", "--now", "dnf-automatic.timer"}}
	act.Timeout = 20 * time.Minute
	act.Warning = "Starts dnf-automatic's timer, which installs updates on its own from then on — and an " +
		"update can restart the service it belongs to. The config edit has a checkpoint; rolling it back also " +
		"stops the timer, but leaves the package installed."
	return Fix{FindingID: f.ID, Label: "Enable automatic security updates (dnf-automatic)",
		Kind: model.RemediationReview, Actions: []Action{act}}, nil
}

// setDnfApplyUpdates sets apply_updates = yes in [commands], in place where
// the key is already there and after the section header where it is not. A
// file created here also gets upgrade_type = security, so a host that never
// configured dnf-automatic gets security updates rather than every update;
// an existing file keeps whatever upgrade_type its operator chose.
func setDnfApplyUpdates(in []byte) ([]byte, error) {
	if strings.TrimSpace(string(in)) == "" {
		return []byte("[commands]\napply_updates = yes\nupgrade_type = security\n"), nil
	}
	lines := strings.SplitAfter(string(in), "\n")
	section, header, done := "", -1, false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.TrimSpace(t[1 : len(t)-1])
			if section == "commands" {
				header = i
			}
			continue
		}
		if section != "commands" || t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		if k, _, ok := strings.Cut(t, "="); ok && strings.TrimSpace(k) == "apply_updates" {
			lines[i] = "apply_updates = yes\n"
			done = true
		}
	}
	out := strings.Join(lines, "")
	switch {
	case done:
	case header >= 0:
		lines[header] = strings.TrimRight(lines[header], "\n") + "\napply_updates = yes\n"
		out = strings.Join(lines, "")
	default:
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += "\n[commands]\napply_updates = yes\n"
	}
	return []byte(out), nil
}

// aptPeriodicKeys are the two directives that switch apt's periodic upgrades
// on. Both are needed: the first refreshes the package lists, the second
// installs from them, and setting only the second gives a host that faithfully
// applies updates it never learns about.
var aptPeriodicKeys = []struct{ key, value string }{
	{"APT::Periodic::Update-Package-Lists", "1"},
	{"APT::Periodic::Unattended-Upgrade", "1"},
}

// enableAptPeriodic writes the periodic keys into apt's config, creating the
// file when it is not there — which is the ordinary case, because a host that
// has never had automatic updates configured has no 20auto-upgrades at all.
//
// Existing values are rewritten in place rather than appended to. apt reads
// the last assignment, so appending would work and would leave a file with the
// same key twice, one of them a lie; and the rollback would restore a file
// whose meaning depended on line order.
func enableAptPeriodic(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s does not name apt's periodic config", f.ID)
	}
	return Fix{
		FindingID: f.ID,
		Label:     "Enable automatic security updates (unattended-upgrades)",
		Kind:      model.RemediationAuto,
		Actions: []Action{{
			Label:           "Switch on apt's periodic update and unattended-upgrade keys",
			Benefit:         autoUpdatesBenefit,
			Kind:            ActionEdit,
			Path:            path,
			CreateIfMissing: true,
			Transform:       setAptPeriodic,
		}},
	}, nil
}

func setAptPeriodic(in []byte) ([]byte, error) {
	out := string(in)
	for _, k := range aptPeriodicKeys {
		re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(k.key) + `[ \t]+"[^"]*"[ \t]*;[ \t]*$`)
		line := k.key + ` "` + k.value + `";`
		if re.MatchString(out) {
			out = re.ReplaceAllString(out, line)
			continue
		}
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += line + "\n"
	}
	return []byte(out), nil
}

// execFix builds a single-action Auto exec fix. EffectiveKind floors every
// caller to Review since the action is exec, so warning is what a person
// reviewing it actually reads before deciding — the same job
// firewall.go's hand-written Warnings do, and this package's calls were
// missing entirely until a demo-VM rehearsal of the Review workflow found the
// preview for updates.pending-security carrying no warning at all next to
// one that did.
func execFix(label, actionLabel, benefit, warning string, commands [][]string) Fix {
	return Fix{
		Label: label,
		Kind:  model.RemediationAuto,
		Actions: []Action{{
			Label:    actionLabel,
			Benefit:  benefit,
			Warning:  warning,
			Kind:     ActionExec,
			Commands: commands,
		}},
	}
}
