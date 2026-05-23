package host

import "github.com/seolcu/hostveil/internal/domain"

type UpdatesCheck struct{ Root string }

func (c *UpdatesCheck) Name() string { return "updates" }

func (c *UpdatesCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			domain.FindingHostUpdatesUnattended,
			domain.AxisUpdateSupplyChain,
			domain.SeverityMedium,
			"updates",
			"Unattended security upgrades not configured",
			"Check whether unattended-upgrades is installed and configured for security updates.",
			"Without automatic security updates, critical patches may be delayed for weeks or months.",
			"Install unattended-upgrades: sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades",
		),
		hostFinding(
			domain.FindingHostUpdatesReboot,
			domain.AxisUpdateSupplyChain,
			domain.SeverityLow,
			"updates",
			"System may require a reboot for updates",
			"Check whether a reboot is pending due to kernel or library updates.",
			"Running an outdated kernel leaves the system vulnerable to known exploits.",
			"Reboot the system to apply pending updates: sudo reboot",
		),
	}
}
