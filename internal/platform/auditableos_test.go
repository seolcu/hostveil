package platform

import (
	"strings"
	"testing"
)

// hostveil publishes darwin archives, and every detection rule in it is about
// Linux. Most domains work that out for themselves — no /proc/sys, no
// systemd, no apt-get, no ss — and skip cleanly. Three did not, and each
// turned "I could not look" into an answer.
//
// The worst was firewall: it probes ufw, firewall-cmd, nft and iptables, none
// of which exists on macOS, so nothing failed and the absence of a failure
// read as the absence of a firewall. Every Mac got a top-severity
// `firewall.inactive` for a host whose packet filter is pf.
//
// This is the rule that stops it. It is tested by argument rather than by
// runtime.GOOS because the case that matters is the platform CI never runs.
func TestAuditableOS(t *testing.T) {
	for _, tc := range []struct {
		goos string
		want bool
	}{
		{"linux", true},
		{"darwin", false},
		{"windows", false},
		{"freebsd", false},
		{"", false},
	} {
		got, why := auditableOS(tc.goos)
		if got != tc.want {
			t.Errorf("auditableOS(%q) = %v, want %v", tc.goos, got, tc.want)
		}
		switch {
		case got && why != "":
			t.Errorf("auditableOS(%q) is auditable but gave a reason %q", tc.goos, why)
		case !got && why == "":
			t.Errorf("auditableOS(%q) is not auditable and gave no reason — the reason is what "+
				"the user sees in place of a finding", tc.goos)
		case !got && !strings.Contains(why, tc.goos):
			t.Errorf("auditableOS(%q) does not name the OS in its reason: %q", tc.goos, why)
		}
	}
}

// The empty string is not auditable on purpose. It cannot arise in
// production — runtime.GOOS is a compile-time constant and never empty — so
// the only way to reach it is a caller passing something it did not detect,
// and "I do not know what this host is" must not resolve to "Linux, carry on".
func TestAnUnknownOSIsNotAudited(t *testing.T) {
	if ok, _ := auditableOS(""); ok {
		t.Error("an unknown operating system was treated as auditable")
	}
}

// The build hostveil actually runs its tests on.
func TestThisBuildIsAuditable(t *testing.T) {
	if ok, why := AuditableOS(); !ok {
		t.Skipf("this build is not auditable (%s) — the checker tests below it will skip too", why)
	}
}
