package host

import "github.com/seolcu/hostveil/internal/domain"

type SSHCheck struct{ Root string }

func (c *SSHCheck) Name() string { return "ssh" }

func (c *SSHCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			domain.FindingHostSSHRootLogin,
			domain.AxisHostHardening,
			domain.SeverityHigh,
			"ssh",
			"SSH root login may be permitted",
			"Check whether PermitRootLogin is disabled in /etc/ssh/sshd_config.",
			"Root login via SSH bypasses audit trails and allows direct privilege escalation.",
			"Set PermitRootLogin no in /etc/ssh/sshd_config and use sudo instead.",
		),
		hostFinding(
			domain.FindingHostSSHPasswordAuth,
			domain.AxisHostHardening,
			domain.SeverityMedium,
			"ssh",
			"SSH password authentication may be enabled",
			"Check whether PasswordAuthentication is disabled in /etc/ssh/sshd_config.",
			"Password-based SSH is vulnerable to brute force attacks. Key-based auth is more secure.",
			"Set PasswordAuthentication no and use SSH keys only.",
		),
		hostFinding(
			domain.FindingHostSSHProtocol,
			domain.AxisHostHardening,
			domain.SeverityLow,
			"ssh",
			"SSH protocol version should be 2",
			"Check whether the SSH server only accepts protocol version 2.",
			"Protocol 1 has known vulnerabilities and should be disabled.",
			"Set Protocol 2 in /etc/ssh/sshd_config.",
		),
	}
}
