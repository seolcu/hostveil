package host

import "github.com/seolcu/hostveil/internal/domain"

type KernelCheck struct{ Root string }

func (c *KernelCheck) Name() string { return "kernel" }

func (c *KernelCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			domain.FindingHostKernelUpdates,
			domain.AxisUpdateSupplyChain,
			domain.SeverityHigh,
			"kernel",
			"Kernel may be outdated",
			"Check the running kernel version against the latest available.",
			"Unpatched kernels are vulnerable to known privilege escalation and container escape exploits.",
			"Update the kernel: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
		),
		hostFinding(
			domain.FindingHostKernelCoreDumps,
			domain.AxisHostHardening,
			domain.SeverityLow,
			"kernel",
			"Core dumps may not be restricted",
			"Check whether core dumps are limited or disabled.",
			"Core dumps can contain sensitive data from crashed processes, including passwords and keys.",
			"Set ulimit -c 0 in /etc/security/limits.conf or set kernel.core_pattern to /dev/null.",
		),
		hostFinding(
			domain.FindingHostKernelIPForward,
			domain.AxisHostHardening,
			domain.SeverityLow,
			"kernel",
			"IP forwarding may be enabled",
			"Check whether net.ipv4.ip_forward is enabled.",
			"IP forwarding turns the host into a router, which can be used for network pivoting by attackers.",
			"Disable if not needed: sudo sysctl -w net.ipv4.ip_forward=0",
		),
	}
}
