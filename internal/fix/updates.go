package fix

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerUpdates wires the auto-update fix into the registry.
func registerUpdates(r *Registry) {
	r.Register("updates.disabled", buildEnableAutoUpdates)
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
