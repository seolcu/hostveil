package fix

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// HostEdit defines a file edit on the host system.
type HostEdit struct {
	Path            string
	Summary         string
	OriginalContent string
	UpdatedContent  string
	Mode            os.FileMode
}

// ShellCommand defines a shell command to run on the host.
type ShellCommand struct {
	Command string
	Summary string
	Rollback string
}

// PrepareHostEdit creates a FixAction for a host file edit.
func PrepareHostEdit(path, summary, original, updated string, mode os.FileMode) FixAction {
	return FixAction{
		Type:    ActionHostEdit,
		Summary: summary,
		Path:    path,
		Content: original,
		Diff:    updated,
	}
}

// PrepareShellCommand creates a FixAction for a shell command.
func PrepareShellCommand(cmd, summary, rollback string) FixAction {
	return FixAction{
		Type:    ActionShellCommand,
		Summary: summary,
		Command: cmd,
		Rollback: rollback,
	}
}

// ApplyHostEdit writes the updated content to the specified path.
// Creates a backup with .bak suffix before modifying.
func ApplyHostEdit(edit FixAction) error {
	if edit.Type != ActionHostEdit {
		return fmt.Errorf("expected HostEdit action, got %d", edit.Type)
	}

	// Create backup
	if _, err := os.Stat(edit.Path); err == nil {
		data, err := os.ReadFile(edit.Path)
		if err != nil {
			return fmt.Errorf("read %s: %w", edit.Path, err)
		}
		backupPath := edit.Path + ".bak"
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return fmt.Errorf("backup %s: %w", edit.Path, err)
		}
	}

	return os.WriteFile(edit.Path, []byte(edit.Diff), 0644)
}

// ApplyShellCommand executes a shell command on the host.
// Returns the combined stdout/stderr output.
func ApplyShellCommand(action FixAction) (string, error) {
	if action.Type != ActionShellCommand {
		return "", fmt.Errorf("expected ShellCommand action, got %d", action.Type)
	}

	cmd := exec.Command("sh", "-c", action.Command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w\noutput: %s", err, string(output))
	}

	return string(output), nil
}

// hostEditsForFinding generates host edit actions for a given finding.
// Called by the fix engine during preview/apply.
func hostEditsForFinding(findingID string, svc string) []FixAction {
	switch findingID {
	case "host.ssh.root_login":
		return []FixAction{
			PrepareHostEdit(
				"/etc/ssh/sshd_config",
				"Disable SSH root login: set PermitRootLogin no",
				"#PermitRootLogin prohibit-password",
				"PermitRootLogin no",
				0644,
			),
			PrepareShellCommand(
				"systemctl restart sshd",
				"Restart SSH daemon to apply changes",
				"systemctl restart sshd",
			),
		}

	case "host.ssh.password_auth":
		return []FixAction{
			PrepareHostEdit(
				"/etc/ssh/sshd_config",
				"Disable SSH password authentication",
				"#PasswordAuthentication yes",
				"PasswordAuthentication no",
				0644,
			),
			PrepareShellCommand(
				"systemctl restart sshd",
				"Restart SSH to apply password auth change",
				"systemctl restart sshd",
			),
		}

	case "host.firewall.no_active_firewall":
		return []FixAction{
			PrepareShellCommand(
				"ufw --force enable",
				"Enable UFW firewall",
				"ufw disable",
			),
		}

	case "host.defenses.fail2ban_not_installed":
		return []FixAction{
			PrepareShellCommand(
				"apt-get install -y fail2ban && systemctl enable --now fail2ban",
				"Install and start fail2ban",
				"apt-get remove -y fail2ban",
			),
		}

	case "host.mac.no_apparmor":
		return []FixAction{
			PrepareShellCommand(
				"apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor",
				"Install and enable AppArmor",
				"apt-get remove -y apparmor apparmor-utils",
			),
		}
	}

	return nil
}

// adapterFixForFinding maps external adapter findings to fix actions.
// This is a minimal implementation — see issue #385 for full classification.
func adapterFixForFinding(findingID string, svc string) []FixAction {
	if strings.HasPrefix(findingID, "trivy.") {
		return []FixAction{
			PrepareShellCommand(
				fmt.Sprintf("docker pull %s", svc),
				"Pull latest image to update vulnerable packages",
				"",
			),
		}
	}

	if strings.HasPrefix(findingID, "dockle.") {
		return []FixAction{
			PrepareHostEdit(
				"Dockerfile",
				"Review Dockle best practice finding. Manual edit may be required.",
				"",
				"",
				0644,
			),
		}
	}

	return nil
}
