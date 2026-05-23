package host

import "github.com/seolcu/hostveil/internal/domain"

type FilesystemCheck struct{ Root string }

func (c *FilesystemCheck) Name() string { return "filesystem" }

func (c *FilesystemCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			domain.FindingHostFilesystemWorldWritable,
			domain.AxisExcessivePermissions,
			domain.SeverityMedium,
			"filesystem",
			"World-writable system files or directories exist",
			"Check for world-writable permissions on critical system paths.",
			"World-writable system files allow any local user to modify system behavior and escalate privileges.",
			"Remove world-writable permissions: sudo chmod o-w /path/to/file",
		),
		hostFinding(
			domain.FindingHostFilesystemSUID,
			domain.AxisExcessivePermissions,
			domain.SeverityMedium,
			"filesystem",
			"SUID binaries may be exploitable",
			"Check for world-writable SUID binaries that could be used for privilege escalation.",
			"SUID binaries run with the file owner's privileges. Exploitable SUID binaries are a common escalation vector.",
			"Remove SUID from suspicious binaries: sudo chmod u-s /path/to/binary",
		),
		hostFinding(
			domain.FindingHostFilesystemSeparateParts,
			domain.AxisHostHardening,
			domain.SeverityLow,
			"filesystem",
			"Critical directories may not be on separate partitions",
			"Check whether /tmp, /var, and /home are on separate partitions.",
			"Separate partitions prevent a single directory from filling the root filesystem and allow different mount options.",
			"Create separate partitions for /tmp (with noexec), /var, and /home.",
		),
	}
}
