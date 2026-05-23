package host

import "github.com/seolcu/hostveil/internal/domain"

type MACCheck struct{ Root string }

func (c *MACCheck) Name() string { return "mac" }

func (c *MACCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			domain.FindingHostMACNoAppArmor,
			domain.AxisHostHardening,
			domain.SeverityMedium,
			"mac",
			"AppArmor may not be enabled",
			"Check whether AppArmor or SELinux is active on the system.",
			"Mandatory Access Control limits what processes can do even when compromised.",
			"Install and enable AppArmor: sudo apt install apparmor apparmor-utils && sudo systemctl enable apparmor",
		),
		hostFinding(
			domain.FindingHostMACNoSELinux,
			domain.AxisHostHardening,
			domain.SeverityMedium,
			"mac",
			"SELinux may not be in enforcing mode",
			"Check whether SELinux is set to enforcing mode.",
			"SELinux in permissive mode logs violations but does not enforce policy, giving a false sense of security.",
			"Set SELINUX=enforcing in /etc/selinux/config.",
		),
	}
}
