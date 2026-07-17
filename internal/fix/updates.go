package fix

import (
	"fmt"

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
