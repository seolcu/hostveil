package fix

import (
	"testing"
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
