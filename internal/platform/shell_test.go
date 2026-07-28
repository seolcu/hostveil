package platform

import "testing"

func TestIsNonLoginShell(t *testing.T) {
	for _, tc := range []struct {
		shell string
		want  bool
		why   string
	}{
		// The two paths the old account-domain list knew.
		{"/usr/sbin/nologin", true, "Debian, Ubuntu"},
		{"/sbin/nologin", true, "RHEL, Fedora"},
		// The ones it did not, which is the bug this replaced.
		{"/usr/bin/nologin", true, "Arch"},
		{"/run/current-system/sw/bin/nologin", true, "NixOS"},
		{"/usr/local/sbin/nologin", true, "hand-built"},
		{"nologin", true, "no path at all"},

		{"/bin/false", true, ""},
		{"/usr/bin/false", true, ""},
		{"/bin/true", true, "exits successfully and immediately"},
		{"", true, "no shell recorded"},
		{"   ", true, "whitespace only"},
		{"  /usr/sbin/nologin  ", true, "passwd fields can carry stray space"},

		// Real login shells must stay logins, or the empty-password finding
		// stops firing on the accounts it exists for.
		{"/bin/bash", false, ""},
		{"/bin/sh", false, ""},
		{"/usr/bin/zsh", false, ""},
		{"/usr/bin/fish", false, ""},
		// Names that merely contain a keyword are not it.
		{"/bin/falsehood", false, "substring, not the program"},
		{"/usr/bin/nologind", false, "substring, not the program"},
		{"/opt/truecrypt/bin/truecrypt", false, "substring, not the program"},
	} {
		if got := IsNonLoginShell(tc.shell); got != tc.want {
			t.Errorf("IsNonLoginShell(%q) = %v, want %v (%s)", tc.shell, got, tc.want, tc.why)
		}
	}
}
