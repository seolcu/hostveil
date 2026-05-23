package host

import "github.com/seolcu/hostveil/internal/domain"

type DefensesCheck struct{ Root string }

func (c *DefensesCheck) Name() string { return "defenses" }

func (c *DefensesCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			domain.FindingHostDefensesFail2ban,
			domain.AxisHostHardening,
			domain.SeverityMedium,
			"defenses",
			"Fail2ban is not installed",
			"Check whether fail2ban is installed and active on the system.",
			"Fail2ban protects against brute force attacks by temporarily banning offending IPs.",
			"Install fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban",
		),
		hostFinding(
			domain.FindingHostDefensesRkhunter,
			domain.AxisHostHardening,
			domain.SeverityLow,
			"defenses",
			"Rootkit hunter not detected",
			"Check whether rkhunter or chkrootkit is installed.",
			"Rootkit detectors can identify signs of compromise that other tools might miss.",
			"Install rkhunter: sudo apt install rkhunter && sudo rkhunter --check",
		),
		hostFinding(
			domain.FindingHostDefensesAuditd,
			domain.AxisHostHardening,
			domain.SeverityMedium,
			"defenses",
			"System audit daemon not detected",
			"Check whether auditd is installed and collecting logs.",
			"System auditing is essential for detecting and investigating security incidents.",
			"Install auditd: sudo apt install auditd && sudo systemctl enable auditd",
		),
	}
}
