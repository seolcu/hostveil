package fix

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
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
// Full coverage of all host check findings from internal/scanner/host/.
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

	case "host.ssh.protocol":
		return []FixAction{
			PrepareHostEdit(
				"/etc/ssh/sshd_config",
				"Set SSH protocol to version 2 only",
				"#Protocol 2",
				"Protocol 2",
				0644,
			),
			PrepareShellCommand(
				"systemctl restart sshd",
				"Restart SSH to apply protocol change",
				"systemctl restart sshd",
			),
		}

	case "host.docker.socket_accessible":
		return []FixAction{
			PrepareShellCommand(
				"usermod -aG docker root && chmod 660 /var/run/docker.sock",
				"Restrict Docker socket permissions",
				"chmod 666 /var/run/docker.sock",
			),
			PrepareShellCommand(
				"echo 'Consider using rootless Docker for production: https://docs.docker.com/engine/security/rootless/'",
				"Recommend rootless Docker setup",
				"",
			),
		}

	case "host.docker.daemon_tls":
		return []FixAction{
			PrepareHostEdit(
				"/etc/docker/daemon.json",
				"Enable Docker daemon TLS configuration",
				"{}",
				`{"tls":true,"tlsverify":true,"tlscacert":"/etc/docker/ca.pem","tlscert":"/etc/docker/server-cert.pem","tlskey":"/etc/docker/server-key.pem"}`,
				0644,
			),
			PrepareShellCommand(
				"systemctl restart docker",
				"Restart Docker to apply TLS changes",
				"systemctl restart docker",
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

	case "host.firewall.default_drop":
		return []FixAction{
			PrepareShellCommand(
				"iptables -P INPUT DROP && iptables -P FORWARD DROP",
				"Set firewall default policies to DROP",
				"iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT",
			),
		}

	case "host.kernel.kernel_updates":
		return []FixAction{
			PrepareShellCommand(
				"apt-get update && apt-get upgrade -y linux-image-$(uname -r)",
				"Update kernel to latest available version",
				"",
			),
		}

	case "host.kernel.core_dumps":
		return []FixAction{
			PrepareHostEdit(
				"/etc/security/limits.conf",
				"Disable core dumps via limits.conf",
				"",
				"* hard core 0",
				0644,
			),
			PrepareShellCommand(
				"sysctl -w kernel.core_pattern=/dev/null && echo 'kernel.core_pattern=/dev/null' >> /etc/sysctl.conf",
				"Disable core dumps via sysctl",
				"sysctl -w kernel.core_pattern=core",
			),
		}

	case "host.kernel.ip_forwarding":
		return []FixAction{
			PrepareShellCommand(
				"sysctl -w net.ipv4.ip_forward=0 && sysctl -w net.ipv6.conf.all.forwarding=0",
				"Disable IP forwarding",
				"sysctl -w net.ipv4.ip_forward=1",
			),
		}

	case "host.filesystem.world_writable_files":
		return []FixAction{
			PrepareShellCommand(
				"find /etc -type f -perm -o+w 2>/dev/null | xargs -r chmod o-w",
				"Remove world-writable permissions from /etc",
				"",
			),
		}

	case "host.filesystem.suid_files":
		return []FixAction{
			PrepareShellCommand(
				"find /usr -type f -perm -4000 -exec chmod u-s {} \\; 2>/dev/null || true",
				"Remove SUID bit from /usr binaries (may break functionality)",
				"",
			),
		}

	case "host.fim.no_fim_tool":
		return []FixAction{
			PrepareShellCommand(
				"apt-get install -y aide && aideinit",
				"Install and initialize AIDE file integrity checker",
				"apt-get remove -y aide",
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

	case "host.mac.no_selinux":
		return []FixAction{
			PrepareHostEdit(
				"/etc/selinux/config",
				"Set SELinux to enforcing mode",
				"SELINUX=disabled",
				"SELINUX=enforcing",
				0644,
			),
			PrepareShellCommand(
				"setenforce 1",
				"Set SELinux to enforcing immediately",
				"setenforce 0",
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

	case "host.defenses.rkhunter_not_installed":
		return []FixAction{
			PrepareShellCommand(
				"apt-get install -y rkhunter && rkhunter --propupd",
				"Install and initialize rootkit hunter",
				"apt-get remove -y rkhunter",
			),
		}

	case "host.defenses.auditd_not_installed":
		return []FixAction{
			PrepareShellCommand(
				"apt-get install -y auditd && systemctl enable --now auditd",
				"Install and start auditd",
				"apt-get remove -y auditd",
			),
		}

	case "host.updates.unattended_upgrades":
		return []FixAction{
			PrepareShellCommand(
				"apt-get install -y unattended-upgrades && dpkg-reconfigure -f noninteractive unattended-upgrades",
				"Install and configure unattended security upgrades",
				"apt-get remove -y unattended-upgrades",
			),
		}

	case "host.updates.reboot_required":
		return []FixAction{
			PrepareShellCommand(
				"shutdown -r +5 'Hostveil: rebooting to apply kernel updates'",
				"Schedule reboot for pending updates",
				"shutdown -c",
			),
		}
	}

	return nil
}

// adapterFixForFinding maps external adapter findings to fix actions.
func adapterFixForFinding(finding domain.Finding) []FixAction {
	id := finding.ID
	svc := finding.Service

	switch {
	case strings.HasPrefix(id, "trivy."):
		actions := []FixAction{
			PrepareShellCommand(
				fmt.Sprintf("docker pull %s", svc),
				fmt.Sprintf("Pull latest %s image to update vulnerable packages", svc),
				"",
			),
		}
		if pkg, ok := finding.Evidence["package"]; ok {
			if fixed, ok := finding.Evidence["fixed_version"]; ok {
				actions = append(actions, PrepareShellCommand(
					fmt.Sprintf("echo 'Update %s to version %s or later and rebuild the image'", pkg, fixed),
					fmt.Sprintf("Specific package fix: %s → %s", pkg, fixed),
					"",
				))
			}
		}
		actions = append(actions, PrepareShellCommand(
			fmt.Sprintf("docker build --no-cache -t %s . && docker push %s", svc, svc),
			fmt.Sprintf("Rebuild %s with updated base image to fix vulnerabilities", svc),
			"",
		))
		return actions

	case strings.HasPrefix(id, "dockle."):
		code := strings.TrimPrefix(id, "dockle.")
		return []FixAction{
			PrepareShellCommand(
				fmt.Sprintf("echo 'Dockle CIS %s: review Dockerfile best practices for %s' >> DOCKLE_FIXES.md", code, svc),
				fmt.Sprintf("Log Dockle CIS %s finding for %s", code, svc),
				"",
			),
			PrepareShellCommand(
				getDockleFixCommand(code, svc),
				fmt.Sprintf("Apply Dockle CIS %s fix for %s", code, svc),
				"",
			),
		}

	case strings.HasPrefix(id, "lynis."):
		return []FixAction{
			PrepareShellCommand(
				fmt.Sprintf("echo 'Lynis hardening: review %s' >> LYNIS_FIXES.md", finding.Title),
				fmt.Sprintf("Log Lynis finding for manual hardening review"),
				"",
			),
			PrepareShellCommand(
				fmt.Sprintf("lynis --check %s", strings.TrimPrefix(id, "lynis.")),
				"Re-run Lynis for this specific check after applying fixes",
				"",
			),
		}

	case strings.HasPrefix(id, "gitleaks."):
		actions := []FixAction{
			PrepareShellCommand(
				fmt.Sprintf("echo 'WARNING: Secret leak detected by Gitleaks (%s). Rotate the credential immediately.'", id),
				fmt.Sprintf("Alert about secret leak %s — manual rotation required", id),
				"",
			),
		}
		if file, ok := finding.Evidence["file"]; ok {
			actions = append(actions, PrepareShellCommand(
				fmt.Sprintf("echo 'Remove secret from %s, add to .gitignore, and rotate the credential'", file),
				fmt.Sprintf("Remove leaked secret from %s", file),
				"",
			))
		}
		actions = append(actions, PrepareShellCommand(
			fmt.Sprintf("BFG_REPO=$(basename $(git rev-parse --show-toplevel 2>/dev/null || echo '.')) && echo 'Run: java -jar bfg.jar --delete-files .env && git reflog expire --expire=now --all && git gc --prune=now --aggressive'"),
			"Provide BFG repo-cleaner instructions for git history cleanup",
			"",
		))
		return actions
	}

	return nil
}

func getDockleFixCommand(code, svc string) string {
	switch code {
	case "CIS-DI-0001":
		return fmt.Sprintf("echo 'USER instruction missing. Add: USER nobody' to Dockerfile for %s", svc)
	case "CIS-DI-0005":
		return fmt.Sprintf("echo 'Enable Docker content trust: export DOCKER_CONTENT_TRUST=1' before building %s", svc)
	case "CIS-DI-0006":
		return fmt.Sprintf("echo 'Add HEALTHCHECK instruction to Dockerfile for %s'", svc)
	case "CIS-DI-0007":
		return fmt.Sprintf("echo 'Remove sudo from %s Dockerfile. Use gosu or su-exec instead.'", svc)
	case "CIS-DI-0008":
		return fmt.Sprintf("echo 'Set USER instruction in %s Dockerfile to non-root user'", svc)
	default:
		return fmt.Sprintf("echo 'Review Dockle CIS finding for %s and apply recommended fix' >> DOCKLE_FIXES.md", svc)
	}
}


