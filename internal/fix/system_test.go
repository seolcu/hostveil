package fix

import (
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

func TestSystemFixClassification(t *testing.T) {
	r := New()
	registerSystemFixes(r)

	tests := []struct {
		id   string
		kind domain.RemediationKind
	}{
		// Should stay AUTO
		{"lynis.FILE-6310", domain.RemediationAuto},
		{"lynis.KRNL-5830", domain.RemediationAuto},
		// Downgraded to REVIEW
		{"lynis.AUTH-9286", domain.RemediationReview},
		{"lynis.KRNL-5780", domain.RemediationReview},
		{"lynis.ACCT-9626", domain.RemediationReview},
		{"lynis.LOGG-2100", domain.RemediationReview},
		// Already REVIEW
		{"lynis.FIRE-4512", domain.RemediationReview},
		// Downgraded to MANUAL
		{"lynis.AUTH-9265", domain.RemediationManual},
		{"lynis.HRMN-6114", domain.RemediationManual},
		{"lynis.BOOT-5120", domain.RemediationReview},
		{"lynis.AUTH-9328", domain.RemediationManual},
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
	for _, id := range []string{"lynis.AUTH-9265", "lynis.HRMN-6114", "lynis.AUTH-9328"} {
		f := r.Lookup(id)
		if f == nil {
			continue
		}
		if len(f.Actions) != 0 {
			t.Errorf("%s should have 0 actions, got %d", id, len(f.Actions))
		}
	}
}
