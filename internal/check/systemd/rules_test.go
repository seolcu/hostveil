package systemd

import (
	"strings"
	"testing"
)

// TestTheDropInNameSortsAfterEveryLoadedOne.
//
// systemd.unit(5): "Multiple drop-in files with different names are applied in
// lexicographic order, regardless of which of the directories they reside in."
// The /etc-over-/usr rule applies only to files with the *same* name — so a
// vendor's /usr/lib/.../90-vendor.conf beats /etc/.../50-hostveil.conf, and a
// fix that wrote the second would be overridden at the next daemon-reload
// having reported success and taken a checkpoint.
//
// This is the same hazard persistSysctl resolves for sysctl.d, and until now
// it was also the stated reason dockerd.socket-world-writable is declined
// while this domain wrote a drop-in with no resolution at all.
func TestTheDropInNameSortsAfterEveryLoadedOne(t *testing.T) {
	const unit = "app.service"
	dir := "/etc/systemd/system/" + unit + ".d/"

	for _, tc := range []struct {
		name, loaded, want string
	}{
		{"no drop-ins at all", "", dir + "50-hostveil.conf"},
		{"one that sorts before", "/usr/lib/systemd/system/service.d/10-timeout-abort.conf", dir + "50-hostveil.conf"},
		{"a vendor file that sorts after", "/usr/lib/systemd/system/app.service.d/90-vendor.conf", dir + "99-hostveil.conf"},
		{"several, the last one deciding",
			"/usr/lib/systemd/system/service.d/10-timeout-abort.conf /etc/systemd/system/app.service.d/60-local.conf",
			dir + "99-hostveil.conf"},
		{"one that outranks anything we would write", "/etc/systemd/system/app.service.d/zz-final.conf", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dropInPath(unit, tc.loaded); got != tc.want {
				t.Errorf("dropInPath(%q) = %q, want %q", tc.loaded, got, tc.want)
			}
		})
	}
}

// And the instruction changes with it: a finding hostveil cannot fix by
// writing a file must not tell the reader to write one.
func TestTheInstructionNamesTheFileThatOutranksIt(t *testing.T) {
	u := unit{ID: "app.service", DropInPaths: "/etc/systemd/system/app.service.d/zz-final.conf"}
	got := howToFix(u, rules[0])
	if strings.Contains(got, "Create /etc/") {
		t.Errorf("the instruction still says to create a file that would be overridden:\n%s", got)
	}
	if !strings.Contains(got, "zz-final.conf") {
		t.Errorf("the instruction does not name the drop-in that outranks it:\n%s", got)
	}
}
