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

func buildApplySecurityUpdates(f model.Finding) (Fix, error) {
	var built Fix
	switch f.Evidence["package-manager"] {
	case "apt":
		built = execFix("Apply pending security updates", "Refresh apt metadata and fully upgrade installed packages", [][]string{{"apt-get", "update"}, {"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "dist-upgrade", "-y"}})
	case "dnf":
		built = execFix("Apply pending security updates", "Upgrade packages covered by security advisories", [][]string{{"dnf", "upgrade", "-y", "--security"}})
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
	}
	built := execFix("Install host-hardening package "+pkg, "Install and enable "+pkg, commands)
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
			"Install and enable unattended-upgrades", [][]string{
				{"apt-get", "install", "-y", "unattended-upgrades"},
				{"systemctl", "enable", "--now", "unattended-upgrades.service"},
			}), nil
	case "dnf-automatic":
		return execFix("Enable automatic security updates (dnf-automatic)",
			"Install and enable dnf-automatic", [][]string{
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

// execFix builds a single-action Auto exec fix.
func execFix(label, actionLabel string, commands [][]string) Fix {
	return Fix{
		Label: label,
		Kind:  model.RemediationAuto,
		Actions: []Action{{
			Label:    actionLabel,
			Kind:     ActionExec,
			Commands: commands,
		}},
	}
}
