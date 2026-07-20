// Package updates implements a native checker for automatic security
// updates. It verifies that the host is set up to apply security patches
// on its own (unattended-upgrades on apt systems, dnf-automatic on dnf
// systems) rather than relying on the operator to remember.
package updates

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports whether automatic security updates are enabled.
type Checker struct {
	// AptConfigPath is the apt periodic-upgrade config; overridable for tests.
	AptConfigPath string
}

// New returns an updates checker.
func New() *Checker {
	return &Checker{AptConfigPath: "/etc/apt/apt.conf.d/20auto-upgrades"}
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

// Check dispatches to the package-manager-specific verification. Available
// has already ruled out every other package manager.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	switch env.PackageManager {
	case platform.PMApt:
		return c.auditApt(), nil
	case platform.PMDnf:
		return c.auditDnf(ctx, env), nil
	default:
		return nil, fmt.Errorf("unsupported package manager %q: Available should have skipped this checker", env.PackageManager)
	}
}

func (c *Checker) auditApt() []model.Finding {
	if aptUnattendedEnabled(c.AptConfigPath) {
		return nil
	}
	return []model.Finding{disabledFinding("unattended-upgrades",
		"Install and enable unattended-upgrades: `apt install unattended-upgrades` then `dpkg-reconfigure -plow unattended-upgrades`.")}
}

func (c *Checker) auditDnf(ctx context.Context, env platform.Env) []model.Finding {
	out, err := env.Runner.Run(ctx, "systemctl", "is-enabled", "dnf-automatic.timer")
	if err == nil && strings.TrimSpace(string(out)) == "enabled" {
		return nil
	}
	return []model.Finding{disabledFinding("dnf-automatic",
		"Install and enable dnf-automatic: `dnf install dnf-automatic` then `systemctl enable --now dnf-automatic.timer` (configure it to apply security updates).")}
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

func disabledFinding(mechanism, howToFix string) model.Finding {
	return model.NewFinding("updates.disabled", "Automatic security updates are not enabled",
		model.SeverityMedium, model.SourceUpdates, model.RemediationReview,
		model.WithDescription("Without automatic security updates, known vulnerabilities in your OS and its packages stay unpatched until you manually update. Most self-hosters forget, leaving public services exploitable for months."),
		model.WithHowToFix(howToFix),
		model.WithEvidence("mechanism", mechanism),
	)
}
