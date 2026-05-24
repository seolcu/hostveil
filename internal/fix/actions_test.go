package fix

import (
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestPrepareHostEdit(t *testing.T) {
	a := PrepareHostEdit("/etc/test.conf", "Test edit", "old", "new", 0644)
	if a.Type != ActionHostEdit {
		t.Errorf("expected ActionHostEdit, got %d", a.Type)
	}
	if a.Path != "/etc/test.conf" {
		t.Errorf("expected /etc/test.conf, got %s", a.Path)
	}
	if a.Summary != "Test edit" {
		t.Errorf("expected 'Test edit', got %s", a.Summary)
	}
}

func TestPrepareShellCommand(t *testing.T) {
	a := PrepareShellCommand("apt-get update", "Update packages", "apt-get update")
	if a.Type != ActionShellCommand {
		t.Errorf("expected ActionShellCommand, got %d", a.Type)
	}
	if a.Command != "apt-get update" {
		t.Errorf("expected 'apt-get update', got %s", a.Command)
	}
}

func TestHostEditsForFindingCoverage(t *testing.T) {
	// Verify all known host finding IDs produce actions
	cases := []string{
		"host.ssh.root_login",
		"host.ssh.password_auth",
		"host.ssh.protocol",
		"host.docker.socket_accessible",
		"host.docker.daemon_tls",
		"host.firewall.no_active_firewall",
		"host.firewall.default_drop",
		"host.kernel.kernel_updates",
		"host.kernel.core_dumps",
		"host.kernel.ip_forwarding",
		"host.filesystem.world_writable_files",
		"host.filesystem.suid_files",
		"host.fim.no_fim_tool",
		"host.mac.no_apparmor",
		"host.mac.no_selinux",
		"host.defenses.fail2ban_not_installed",
		"host.defenses.rkhunter_not_installed",
		"host.defenses.auditd_not_installed",
		"host.updates.unattended_upgrades",
		"host.updates.reboot_required",
	}

	for _, id := range cases {
		actions := hostEditsForFinding(id, "test")
		if len(actions) == 0 {
			t.Errorf("no actions for %s", id)
		}
	}
}

func TestAdapterFixForFindingCoverage(t *testing.T) {
	cases := []struct {
		finding domain.Finding
		expects int
	}{
		{domain.Finding{ID: "trivy.CVE-2024-0001", Service: "test:latest", Evidence: map[string]string{"package": "curl@7.0", "fixed_version": "7.1"}}, 3},
		{domain.Finding{ID: "lynis.some_test", Service: "test:latest"}, 2},
		{domain.Finding{ID: "unknown.finding", Service: "test:latest"}, 0},
	}

	for _, c := range cases {
		actions := adapterFixForFinding(c.finding)
		if len(actions) != c.expects {
			t.Errorf("adapterFixForFinding(%q) expected %d actions, got %d", c.finding.ID, c.expects, len(actions))
		}
	}
}

func TestHostEditsForFindingReturnsNilForUnknown(t *testing.T) {
	actions := hostEditsForFinding("nonexistent.finding", "test")
	if actions != nil {
		t.Errorf("expected nil for unknown finding, got %d actions", len(actions))
	}
}

func TestAdapterFixForFindingReturnsNilForUnknown(t *testing.T) {
	actions := adapterFixForFinding(domain.Finding{ID: "unknown.finding", Service: "test"})
	if len(actions) != 0 {
		t.Errorf("expected 0 actions for unknown, got %d", len(actions))
	}
}
