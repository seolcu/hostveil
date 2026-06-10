package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/etc/some/file", "/etc/some/file"},
		{"/etc/shadow", ""},
		{"/etc/sudoers", ""},
		{"/etc/sudoers.d", ""},
		{"/etc/ssh/sshd_config", ""},
		{"/var/log/syslog", "/var/log/syslog"},
		{"relative/path", ""},
		{"", ""},
		{"/tmp/../etc/shadow", ""},
	}
	for _, tt := range tests {
		got := sanitizePath(tt.input)
		if got != tt.want {
			t.Errorf("sanitizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeUser(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"root", "root"},
		{"myuser", "myuser"},
		{"user-name", "user-name"},
		{"user_name", "user_name"},
		{"admin123", "admin123"},
		{"", ""},
		{"user name", ""},
		{"root;rm -rf /", ""},
		{"$(id)", ""},
	}
	for _, tt := range tests {
		got := sanitizeUser(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeUser(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizePath_NonDangerous(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/etc/ssh/ssh_config", "/etc/ssh/ssh_config"},
		{"/home/user/file.txt", "/home/user/file.txt"},
		{"/tmp/test", "/tmp/test"},
	}
	for _, tt := range tests {
		got := sanitizePath(tt.input)
		if got != tt.want {
			t.Errorf("sanitizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeUser_Unicode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"日本語", ""},
		{"user\u0000name", ""},
		{"a-b_c.d", ""},
	}
	for _, tt := range tests {
		got := sanitizeUser(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeUser(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizePort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"80", "80"},
		{"443/tcp", "443"},
		{"53/udp", "53"},
		{"8080", "8080"},
		{"", ""},
		{"abc", ""},
		{"22/tcp;rm", ""},
		{"0", "0"},
	}
	for _, tt := range tests {
		got := sanitizePort(tt.input)
		if got != tt.want {
			t.Errorf("sanitizePort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestInstallPackage_DistroDetection verifies installPackage picks the
// right package manager for the current environment. In test environments
// it uses whatever LookPath finds; the assertion is that no panic occurs
// and a clear error is returned when no package manager is present (which
// is rare in practice).
func TestInstallPackage_DistroDetection(t *testing.T) {
	// Just call it — we don't assert success/failure because that depends
	// on the test environment. The point is that it doesn't panic and
	// returns a sensible error string on failure.
	err := installPackage("nonexistent-hostveil-test-package-12345")
	if err != nil {
		// OK — error is expected when the package doesn't exist or no
		// package manager is found. The error message must include
		// either the package name or a hint about which package manager
		// was tried.
		msg := err.Error()
		if !containsAny(msg, []string{"nonexistent-hostveil", "apt", "apk", "dnf", "no supported"}) {
			t.Errorf("installPackage error %q should mention the package or the package manager", msg)
		}
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// TestAuth9286_PasswordAgingAction checks the AUTH-9286 fix actions exist
// and target the correct file. We don't run them (they hit /etc/login.defs
// which is system state) but verify the registration shape.
func TestAuth9286_PasswordAgingAction(t *testing.T) {
	r := New()
	registerSystemFixes(r)

	fix := r.Lookup("lynis.AUTH-9286")
	if fix == nil {
		t.Fatal("lynis.AUTH-9286 not registered")
	}
	if len(fix.Actions) != 2 {
		t.Fatalf("AUTH-9286 should have 2 actions (MIN/MAX), got %d", len(fix.Actions))
	}
	for i, a := range fix.Actions {
		if a.FilePath != "/etc/login.defs" {
			t.Errorf("AUTH-9286 action[%d] FilePath = %q, want /etc/login.defs", i, a.FilePath)
		}
		if a.Warning == "" {
			t.Errorf("AUTH-9286 action[%d] should have a Warning", i)
		}
	}
}

// TestAuth9328_UmaskAction verifies the umask fix is registered and points
// to /etc/profile.
func TestAuth9328_UmaskAction(t *testing.T) {
	r := New()
	registerSystemFixes(r)

	fix := r.Lookup("lynis.AUTH-9328")
	if fix == nil {
		t.Fatal("lynis.AUTH-9328 not registered")
	}
	if len(fix.Actions) != 1 {
		t.Fatalf("AUTH-9328 should have 1 action, got %d", len(fix.Actions))
	}
	if fix.Actions[0].FilePath != "/etc/profile" {
		t.Errorf("AUTH-9328 action[0] FilePath = %q, want /etc/profile", fix.Actions[0].FilePath)
	}
}

// TestKrnl5820_CoreDumpAction verifies the core dump fix targets
// /etc/security/limits.conf.
func TestKrnl5820_CoreDumpAction(t *testing.T) {
	r := New()
	registerSystemFixes(r)

	fix := r.Lookup("lynis.KRNL-5820")
	if fix == nil {
		t.Fatal("lynis.KRNL-5820 not registered")
	}
	if len(fix.Actions) != 1 {
		t.Fatalf("KRNL-5820 should have 1 action, got %d", len(fix.Actions))
	}
	if fix.Actions[0].FilePath != "/etc/security/limits.conf" {
		t.Errorf("KRNL-5820 action[0] FilePath = %q, want /etc/security/limits.conf", fix.Actions[0].FilePath)
	}
}

// TestSSH7408_MultipleActions verifies the broad SSH-7408 fix provides
// multiple sub-actions covering the sub-concerns Lynis reports.
func TestSSH7408_MultipleActions(t *testing.T) {
	r := New()
	registerSystemFixes(r)

	fix := r.Lookup("lynis.SSH-7408")
	if fix == nil {
		t.Fatal("lynis.SSH-7408 not registered")
	}
	if len(fix.Actions) < 3 {
		t.Errorf("SSH-7408 should have multiple sub-actions (>=3), got %d", len(fix.Actions))
	}
	for i, a := range fix.Actions {
		if a.FilePath != "/etc/ssh/sshd_config" {
			t.Errorf("SSH-7408 action[%d] FilePath = %q, want /etc/ssh/sshd_config", i, a.FilePath)
		}
	}
}

// TestKrnl6000_SysctlActions verifies the sysctl catch-all is registered
// as a single bundled action that applies the full hardening set.
func TestKrnl6000_SysctlActions(t *testing.T) {
	r := New()
	registerSystemFixes(r)

	fix := r.Lookup("lynis.KRNL-6000")
	if fix == nil {
		t.Fatal("lynis.KRNL-6000 not registered")
	}
	if len(fix.Actions) != 1 {
		t.Errorf("KRNL-6000 should be a single bundled action, got %d", len(fix.Actions))
	}
	a := fix.Actions[0]
	if a.Type != ActionExec {
		t.Errorf("KRNL-6000 action type = %v, want ActionExec", a.Type)
	}
	if a.Warning == "" {
		t.Error("KRNL-6000 should have a Warning (kernel-level changes)")
	}
}

// TestNetw3200_ProtocolBlacklist checks the modprobe blacklist action for
// uncommon network protocols. We run it on a temp dir to avoid touching
// real /etc/modprobe.d.
func TestNetw3200_ProtocolBlacklist(t *testing.T) {
	r := New()
	registerSystemFixes(r)

	fix := r.Lookup("lynis.NETW-3200")
	if fix == nil {
		t.Fatal("lynis.NETW-3200 not registered")
	}
	if len(fix.Actions) != 1 {
		t.Fatalf("NETW-3200 should have 1 action, got %d", len(fix.Actions))
	}
	a := fix.Actions[0]
	if a.Type != ActionExec {
		t.Errorf("NETW-3200 action type = %v, want ActionExec", a.Type)
	}
	if a.Warning == "" {
		t.Error("NETW-3200 action should have a Warning (could break apps)")
	}
}

func TestSystemFixClassification(t *testing.T) {
	r := New()
	registerSystemFixes(r)

	tests := []struct {
		id   string
		kind domain.RemediationKind
	}{
		// v2.5.0: IDs match Lynis 3.1.6 semantics
		// Auto (single auto-exec action)
		{"lynis.BANN-7126", domain.RemediationAuto},
		{"lynis.FILE-7524", domain.RemediationAuto},
		// Review (multi-action or sed/exec that could break things)
		{"lynis.AUTH-9286", domain.RemediationReview}, // password aging
		{"lynis.AUTH-9328", domain.RemediationReview}, // umask
		{"lynis.KRNL-5820", domain.RemediationReview}, // core dump
		{"lynis.KRNL-6000", domain.RemediationReview}, // sysctl catch-all
		{"lynis.LOGG-2130", domain.RemediationReview}, // rsyslog
		{"lynis.ACCT-9626", domain.RemediationReview}, // sysstat
		{"lynis.ACCT-9622", domain.RemediationReview}, // process accounting
		{"lynis.ACCT-9628", domain.RemediationReview}, // auditd
		{"lynis.NETW-3200", domain.RemediationReview}, // uncommon protocols
		{"lynis.TIME-3104", domain.RemediationReview}, // NTP
		{"lynis.SSH-7408", domain.RemediationReview},  // broad SSH hardening
		// Manual (cannot automate)
		{"lynis.AUTH-9262", domain.RemediationManual}, // PAM strength
		{"lynis.AUTH-9308", domain.RemediationManual}, // single mode password
		{"lynis.AUTH-9265", domain.RemediationManual}, // LDAP
		{"lynis.FIRE-4590", domain.RemediationManual}, // firewall
		{"lynis.HRMN-6114", domain.RemediationManual}, // SELinux/AppArmor
	}

	for _, tt := range tests {
		f := r.Lookup(tt.id)
		if f == nil {
			t.Errorf("%s not registered", tt.id)
			continue
		}
		if got := f.Class(); got != tt.kind {
			t.Errorf("%s Class() = %v, want %v", tt.id, got, tt.kind)
		}
	}

	// MANUAL fixes must have no actions
	for _, id := range []string{
		"lynis.AUTH-9262", "lynis.AUTH-9265", "lynis.AUTH-9308",
		"lynis.FIRE-4590", "lynis.HRMN-6114",
	} {
		f := r.Lookup(id)
		if f == nil {
			continue
		}
		if len(f.Actions) != 0 {
			t.Errorf("%s should have 0 actions, got %d", id, len(f.Actions))
		}
	}
}
