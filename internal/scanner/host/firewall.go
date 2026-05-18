package host

import "github.com/seolcu/hostveil/internal/domain"

type FirewallCheck struct{ Root string }

func (c *FirewallCheck) Name() string { return "firewall" }

func (c *FirewallCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			"host.firewall.no_active_firewall",
			domain.AxisHostHardening,
			domain.SeverityHigh,
			"firewall",
			"No active firewall detected",
			"Check whether iptables, nftables, ufw, or firewalld is active.",
			"A host firewall limits inbound and outbound connections, reducing the attack surface of exposed services.",
			"Install and enable a firewall: apt install ufw && ufw enable",
		),
		hostFinding(
			"host.firewall.default_drop",
			domain.AxisHostHardening,
			domain.SeverityMedium,
			"firewall",
			"Firewall default policy may not be drop",
			"Check whether the firewall's default input policy is DROP or REJECT.",
			"A default ACCEPT policy allows all inbound traffic unless explicitly denied.",
			"Set the default policy to DROP: sudo iptables -P INPUT DROP",
		),
	}
}
