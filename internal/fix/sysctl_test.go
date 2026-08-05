package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func sysctlFinding(setBy string) model.Finding {
	opts := []model.FindingOption{
		model.WithEvidence("set", "kernel.dmesg_restrict=1"),
	}
	if setBy != "" {
		opts = append(opts, model.WithEvidence("set-by", setBy))
	}
	return model.NewFinding("sysctl.dmesg-restrict", "Any user can read the kernel log",
		model.SeverityHardening, model.SourceSysctl, model.RemediationReview, opts...)
}

// persist returns the alternative that survives a reboot — the first action,
// by construction.
func persist(t *testing.T, setBy string) Action {
	t.Helper()
	fx, err := buildSysctl(sysctlFinding(setBy))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(fx); err != nil {
		t.Fatalf("fix does not validate: %v", err)
	}
	return fx.Actions[0]
}

// The failure this exists for. Ubuntu ships /etc/sysctl.d/99-sysctl.conf as a
// symlink to /etc/sysctl.conf, which is therefore read after every drop-in.
// Writing 60-hostveil-dmesg-restrict.conf on such a host changes nothing: the
// file appears, the fix reports success, a checkpoint is recorded, and the old
// value is back at the next boot with nothing anywhere to explain it.
func TestPersistEditsTheFileThatOutranksTheDropIn(t *testing.T) {
	a := persist(t, "/etc/sysctl.conf:65")

	if a.Path != "/etc/sysctl.conf" {
		t.Fatalf("path = %q, want /etc/sysctl.conf — a drop-in there would be overridden", a.Path)
	}
	if a.CreateIfMissing {
		t.Error("the origin file exists by definition; creating it would mean the origin was wrong")
	}

	got, err := a.Transform([]byte("# tuning\nkernel.dmesg_restrict = 0\nvm.swappiness = 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := "# tuning\nkernel.dmesg_restrict = 1\nvm.swappiness = 10\n"
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// A drop-in read *before* ours is overridden by it, so the ordinary
// remediation is correct and nothing should be edited in place.
func TestPersistKeepsTheDropInWhenItStillWins(t *testing.T) {
	a := persist(t, "/etc/sysctl.d/10-distro.conf:1")
	if a.Path != "/etc/sysctl.d/60-hostveil-dmesg-restrict.conf" {
		t.Errorf("path = %q, want the drop-in: 10- is read before 60-", a.Path)
	}
	if strings.Contains(a.Warning, "will not take effect") {
		t.Errorf("this one does take effect: %q", a.Warning)
	}
}

// No file sets the key: the value is the kernel's own default and the drop-in
// is right. This is the path every host without an origin takes.
func TestPersistWritesTheDropInWithNoOrigin(t *testing.T) {
	a := persist(t, "")
	if a.Path != "/etc/sysctl.d/60-hostveil-dmesg-restrict.conf" {
		t.Errorf("path = %q, want the drop-in", a.Path)
	}
	if !a.CreateIfMissing {
		t.Error("the drop-in does not exist yet, so the fix has to create it")
	}
}

// A package's file under /usr/lib is replaced on upgrade, so editing it would
// be undone by something that leaves no history entry and that rollback
// cannot reach. hostveil writes the drop-in and says it will not work, rather
// than reporting a success the next boot contradicts.
func TestPersistDeclinesToEditAPackageOwnedFile(t *testing.T) {
	a := persist(t, "/usr/lib/sysctl.d/99-vendor.conf:3")
	if a.Path != "/etc/sysctl.d/60-hostveil-dmesg-restrict.conf" {
		t.Errorf("path = %q, want the drop-in: /usr/lib is not ours to edit", a.Path)
	}
	if !strings.Contains(a.Warning, "will not take effect") ||
		!strings.Contains(a.Warning, "/usr/lib/sysctl.d/99-vendor.conf") {
		t.Errorf("the warning must name the file that overrides this one: %q", a.Warning)
	}
}

func TestSetSysctlAssignments(t *testing.T) {
	stamp := "\n# by hostveil\n"
	for _, tc := range []struct {
		name  string
		in    string
		pairs []string
		want  string
	}{
		{
			name: "preserves the left-hand side and replaces everything after the =",
			in:   "  -kernel/dmesg_restrict   = 0   # why\n",
			// The left-hand side is preserved byte for byte, so the slash
			// spelling and systemd's leading "-" marker survive. Everything
			// after the "=" goes: sysctl.d has no trailing-comment syntax, so
			// "0   # why" was the value, and keeping any of it would leave a
			// line the loader reads differently than it looks.
			pairs: []string{"kernel.dmesg_restrict=1"},
			want:  "  -kernel/dmesg_restrict   = 1\n",
		},
		{
			name: "rewrites every assignment, not only the winning one",
			// The last wins today; leaving the first contradicting it turns
			// the file into something whose effect has to be derived.
			in:    "kernel.dmesg_restrict = 0\nvm.swappiness = 10\nkernel.dmesg_restrict = 0\n",
			pairs: []string{"kernel.dmesg_restrict=1"},
			want:  "kernel.dmesg_restrict = 1\nvm.swappiness = 10\nkernel.dmesg_restrict = 1\n",
		},
		{
			name:  "appends a key the file does not assign",
			in:    "vm.swappiness = 10\n",
			pairs: []string{"fs.protected_symlinks=1"},
			want:  "vm.swappiness = 10\n\n# by hostveil\nfs.protected_symlinks = 1\n",
		},
		{
			name:  "rewrites one key and appends the other",
			in:    "fs.protected_symlinks = 0\n",
			pairs: []string{"fs.protected_symlinks=1", "fs.protected_hardlinks=1"},
			want:  "fs.protected_symlinks = 1\n\n# by hostveil\nfs.protected_hardlinks = 1\n",
		},
		{
			name:  "leaves commented-out assignments alone",
			in:    "# kernel.dmesg_restrict = 0\nkernel.dmesg_restrict = 0\n",
			pairs: []string{"kernel.dmesg_restrict=1"},
			want:  "# kernel.dmesg_restrict = 0\nkernel.dmesg_restrict = 1\n",
		},
		{
			name: "leaves a glob alone and appends the exact key",
			// A glob selects parameters beyond the one being fixed, so
			// rewriting its value would change others silently.
			in:    "net.ipv4.conf.*.accept_redirects = 1\n",
			pairs: []string{"net.ipv4.conf.all.accept_redirects=0"},
			want:  "net.ipv4.conf.*.accept_redirects = 1\n\n# by hostveil\nnet.ipv4.conf.all.accept_redirects = 0\n",
		},
		{
			name:  "adds the missing trailing newline before appending",
			in:    "vm.swappiness = 10",
			pairs: []string{"kernel.dmesg_restrict=1"},
			want:  "vm.swappiness = 10\n\n# by hostveil\nkernel.dmesg_restrict = 1\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(setSysctlAssignments([]byte(tc.in), tc.pairs, stamp))
			if got != tc.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

// Applying a fix twice is not an error the operator should have to avoid, and
// a file carrying the same line twice is evidence of a tool that does not
// know what it has done.
func TestSetSysctlAssignmentsIsIdempotent(t *testing.T) {
	stamp := "\n# by hostveil\n"
	pairs := []string{"kernel.dmesg_restrict=1"}
	once := setSysctlAssignments([]byte("vm.swappiness = 10\n"), pairs, stamp)
	twice := setSysctlAssignments(once, pairs, stamp)
	if string(once) != string(twice) {
		t.Errorf("second apply changed the file:\n%s\n---\n%s", once, twice)
	}
}

func TestReadAfter(t *testing.T) {
	const dropIn = "/etc/sysctl.d/60-hostveil-dmesg-restrict.conf"
	for _, tc := range []struct {
		origin string
		want   bool
	}{
		// Read after every drop-in, whatever it is named.
		{"/etc/sysctl.conf", true},
		// Ubuntu's symlink to it, which is how the legacy file gets its 99.
		{"/etc/sysctl.d/99-sysctl.conf", true},
		{"/etc/sysctl.d/90-local.conf", true},
		{"/etc/sysctl.d/10-distro.conf", false},
		{"/usr/lib/sysctl.d/50-default.conf", false},
		// Same name in a different directory is masked, never ordered after.
		{"/usr/lib/sysctl.d/60-hostveil-dmesg-restrict.conf", false},
	} {
		if got := readAfter(tc.origin, dropIn); got != tc.want {
			t.Errorf("readAfter(%q) = %v, want %v", tc.origin, got, tc.want)
		}
	}
}

func TestOriginPath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"/etc/sysctl.conf:65", "/etc/sysctl.conf"},
		{"/etc/sysctl.d/90-local.conf:1", "/etc/sysctl.d/90-local.conf"},
		// A path may contain a colon, so the line number is cut from the right.
		{"/etc/odd:name/sysctl.conf:12", "/etc/odd:name/sysctl.conf"},
	} {
		if got := originPath(sysctlFinding(tc.in)); got != tc.want {
			t.Errorf("originPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
