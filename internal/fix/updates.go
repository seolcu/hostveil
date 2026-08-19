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
}

func buildEnableSysstat(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s names no sysstat config", f.ID)
	}
	return Fix{Label: "Enable sysstat activity collection", Kind: model.RemediationAuto, Actions: []Action{{Label: "Set ENABLED to true", Kind: ActionEdit, Path: path, Transform: func(in []byte) ([]byte, error) {
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
	switch f.Evidence["package-manager"] {
	case "apt":
		built = execFix("Apply pending security updates", "Refresh apt metadata and fully upgrade installed packages",
			pendingSecurityWarning,
			[][]string{{"apt-get", "update"}, {"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "dist-upgrade", "-y"}})
	case "dnf":
		built = execFix("Apply pending security updates", "Upgrade packages covered by security advisories",
			pendingSecurityWarning,
			[][]string{{"dnf", "upgrade", "-y", "--security"}})
	default:
		return Fix{}, fmt.Errorf("finding %s has no known package manager", f.ID)
	}
	built.Actions[0].Timeout = 20 * time.Minute
	return built, nil
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
	built := execFix("Install host-hardening package "+pkg, "Install and enable "+pkg, warning, commands)
	built.Actions[0].Timeout = 20 * time.Minute
	return built, nil
}

// buildEnableAutoUpdates installs and enables the distro's automatic
// security-update mechanism, chosen from the finding's evidence.
func buildEnableAutoUpdates(f model.Finding) (Fix, error) {
	switch f.Evidence["mechanism"] {
	case "unattended-upgrades":
		// Where the package is already installed the whole remediation is one
		// config file, which is a file edit: reversible from a checkpoint,
		// and therefore something hostveil can do unattended. That is the
		// common case — Ubuntu ships unattended-upgrades — and it used to be
		// served by the same `apt-get install` the uncommon case needs, which
		// made an exec action out of a two-line edit and put the most ordinary
		// hardening step on this list behind a human.
		if f.Evidence["installed"] == "true" {
			return enableAptPeriodic(f)
		}
		return execFix("Enable automatic security updates (unattended-upgrades)",
			"Install and enable unattended-upgrades",
			"Installs unattended-upgrades and enables its service. There is no rollback checkpoint; "+
				"undoing this means removing the package by hand.",
			[][]string{
				{"apt-get", "install", "-y", "unattended-upgrades"},
				{"systemctl", "enable", "--now", "unattended-upgrades.service"},
			}), nil
	case "dnf-automatic":
		return execFix("Enable automatic security updates (dnf-automatic)",
			"Install and enable dnf-automatic",
			"Installs dnf-automatic and enables its timer. There is no rollback checkpoint; "+
				"undoing this means removing the package by hand.",
			[][]string{
				{"dnf", "install", "-y", "dnf-automatic"},
				{"systemctl", "enable", "--now", "dnf-automatic.timer"},
			}), nil
	default:
		return Fix{}, fmt.Errorf("finding %s has no known update mechanism", f.ID)
	}
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
func execFix(label, actionLabel, warning string, commands [][]string) Fix {
	return Fix{
		Label: label,
		Kind:  model.RemediationAuto,
		Actions: []Action{{
			Label:    actionLabel,
			Warning:  warning,
			Kind:     ActionExec,
			Commands: commands,
		}},
	}
}
