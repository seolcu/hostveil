package sysctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// writeKeys lays out a fake /proc/sys under a temp dir.
func writeKeys(t *testing.T, keys map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for key, val := range keys {
		path := filepath.Join(root, strings.ReplaceAll(key, ".", "/"))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// checkerFor points the checker at a fake /proc/sys and at a configuration
// search path that does not exist. Leaving ConfDirs at the default would read
// the developer's own /etc/sysctl.d, so whether a finding names an origin
// would depend on the machine running the test.
//
// It also pins the container gate to "this is a host". Left at the default it
// reads /.dockerenv and /proc/1 on whatever is running the test, so every
// assertion below about a Review remediation would invert the day these tests
// ran inside a container — which is a normal thing for a CI job to do, and
// would read as the sysctl domain having broken rather than as the test
// having asked the wrong question.
func checkerFor(root string) *Checker {
	c := New()
	c.Root = root
	c.ConfDirs = []string{filepath.Join(root, "no-such-sysctl.d")}
	c.ConfFile = filepath.Join(root, "no-such-sysctl.conf")
	c.InContainer = onAHost
	return c
}

// onAHost and inAContainer are the two answers the gate can give.
func onAHost() (bool, string) { return false, "" }

func inAContainer() (bool, string) { return true, "this is a container (/.dockerenv)" }

// withConf gives the checker a sysctl.d directory holding dropIns (name →
// body) and, when legacy is non-empty, an /etc/sysctl.conf holding it.
func withConf(t *testing.T, c *Checker, dropIns map[string]string, legacy string) *Checker {
	t.Helper()
	dir := t.TempDir()
	for name, body := range dropIns {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c.ConfDirs = []string{dir}
	if legacy != "" {
		// Deliberately not inside dir: the real one lives beside sysctl.d,
		// not in it, and its name would otherwise be sorted in as a drop-in.
		c.ConfFile = filepath.Join(t.TempDir(), "sysctl.conf")
		if err := os.WriteFile(c.ConfFile, []byte(legacy), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func idsOf(fs []model.Finding) map[string]model.Finding {
	m := map[string]model.Finding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

// weakHost is every audited parameter at its weak value.
var weakHost = map[string]string{
	"kernel.kptr_restrict":               "0",
	"kernel.dmesg_restrict":              "0",
	"kernel.sysrq":                       "1",
	"kernel.yama.ptrace_scope":           "0",
	"net.ipv4.tcp_syncookies":            "0",
	"net.ipv4.conf.all.accept_redirects": "1",
	"net.ipv4.conf.all.rp_filter":        "0",
	"fs.protected_symlinks":              "0",
	"fs.protected_hardlinks":             "1",
}

func TestWeakValuesAreFlagged(t *testing.T) {
	fs, err := checkerFor(writeKeys(t, weakHost)).Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	got := idsOf(fs)
	for _, want := range []string{
		"sysctl.kptr-restrict", "sysctl.dmesg-restrict", "sysctl.sysrq",
		"sysctl.ptrace-scope", "sysctl.syncookies", "sysctl.accept-redirects",
		"sysctl.rp-filter", "sysctl.protected-links",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s, got %v", want, fs)
		}
	}
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			t.Errorf("%s: invalid finding: %v", f.ID, err)
		}
		wantKind := model.RemediationAuto
		if f.ID == "sysctl.rp-filter" || f.ID == "sysctl.sysrq" {
			wantKind = model.RemediationReview
		}
		if f.Remediation != wantKind {
			t.Errorf("%s: remediation = %v, want %v", f.ID, f.Remediation, wantKind)
		}
		// Every finding must carry the machine-readable recommendation the
		// fix is built from. Without it the fix errors out at build time
		// and the UI shows a fix button that leads nowhere.
		if f.Evidence["set"] == "" {
			t.Errorf("%s: no 'set' evidence, so no fix can be built from it", f.ID)
		}
		for _, kv := range strings.Split(f.Evidence["set"], ",") {
			k, _, ok := strings.Cut(kv, "=")
			if !ok || k == "" {
				t.Errorf("%s: malformed 'set' evidence %q", f.ID, f.Evidence["set"])
			}
		}
		if !strings.Contains(f.HowToFix, "/etc/sysctl.d") || !strings.Contains(f.HowToFix, "sysctl --system") {
			t.Errorf("%s: how-to-fix must carry the drop-in path and apply command: %q", f.ID, f.HowToFix)
		}
	}
	if ev := got["sysctl.protected-links"].Evidence["value"]; !strings.Contains(ev, "fs.protected_symlinks=0") {
		t.Errorf("protected-links evidence should name the weak key, got %q", ev)
	}
}

func TestHardenedHostIsClean(t *testing.T) {
	fs, err := checkerFor(writeKeys(t, map[string]string{
		"kernel.kptr_restrict":               "1",
		"kernel.dmesg_restrict":              "1",
		"kernel.sysrq":                       "176", // restricted bitmask, not fully enabled
		"kernel.yama.ptrace_scope":           "1",
		"net.ipv4.tcp_syncookies":            "1",
		"net.ipv4.conf.all.accept_redirects": "0",
		"net.ipv4.conf.all.rp_filter":        "2", // loose counts too
		"fs.protected_symlinks":              "1",
		"fs.protected_hardlinks":             "1",
	})).Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("hardened host produced findings: %v", fs)
	}
}

// A knob this kernel does not have (Yama not built, IPv4 disabled) is not a
// finding and not an error: there is nothing to harden.
func TestAbsentKeysAreSilentlyFine(t *testing.T) {
	fs, err := checkerFor(writeKeys(t, map[string]string{
		"kernel.kptr_restrict": "1",
	})).Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatalf("absent keys must not error: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("absent keys must not produce findings, got %v", fs)
	}
}

// A key that exists but cannot be read is ground not covered, and the
// domain must say so — "could not look" never passes for "nothing there".
func TestUnreadableKeyIsPartial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
	root := writeKeys(t, weakHost)
	locked := filepath.Join(root, "net/ipv4/tcp_syncookies")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	fs, err := checkerFor(root).Check(context.Background(), platform.Env{})
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want PartialError for an unreadable key, got %v", err)
	}
	if !strings.Contains(partial.Reason, "net.ipv4.tcp_syncookies") {
		t.Errorf("reason should name the unread key: %q", partial.Reason)
	}
	if len(fs) == 0 {
		t.Error("the readable keys should still have been audited")
	}
	if _, ok := idsOf(fs)["sysctl.syncookies"]; ok {
		t.Error("an unread key must not be guessed into a finding")
	}
}

// The reachable failure this whole file exists for. Ubuntu ships
// /etc/sysctl.d/99-sysctl.conf as a symlink to /etc/sysctl.conf, so a value
// set there is read *after* every drop-in — including the 60-hostveil-*.conf
// the fix writes. Without an origin the finding tells the operator to add a
// drop-in that will be overridden at the next boot, and nothing anywhere says
// why the value came back.
func TestLegacyConfFileIsNamedAsTheOrigin(t *testing.T) {
	c := withConf(t, checkerFor(writeKeys(t, weakHost)), map[string]string{
		"10-distro.conf": "kernel.dmesg_restrict = 1\n",
	}, "# operator settings\nkernel.dmesg_restrict = 0\n")

	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	f := idsOf(fs)["sysctl.dmesg-restrict"]

	if got := f.Evidence["set-by"]; got != c.ConfFile+":2" {
		t.Errorf("set-by = %q, want %q — the legacy file is read after every drop-in", got, c.ConfFile+":2")
	}
	if strings.Contains(f.HowToFix, "Add `") {
		t.Errorf("how-to-fix still recommends a drop-in that would be overridden:\n%s", f.HowToFix)
	}
	if !strings.Contains(f.HowToFix, c.ConfFile) {
		t.Errorf("how-to-fix must name the file to edit:\n%s", f.HowToFix)
	}
}

// Between two drop-ins the later file name wins, which is systemd-sysctl's
// own rule and the reason it logs "Overwriting earlier assignment".
func TestTheLastDropInWins(t *testing.T) {
	c := withConf(t, checkerFor(writeKeys(t, weakHost)), map[string]string{
		"10-distro.conf": "kernel.dmesg_restrict = 1\n",
		"90-local.conf":  "kernel.dmesg_restrict = 0\n",
	}, "")

	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(c.ConfDirs[0], "90-local.conf") + ":1"
	if got := idsOf(fs)["sysctl.dmesg-restrict"].Evidence["set-by"]; got != want {
		t.Errorf("set-by = %q, want %q", got, want)
	}
}

// A file that sets a value other than the one running is not why the
// parameter is weak — something set it at runtime. Naming it would send the
// operator to edit a line that already says the right thing.
func TestAFileSettingADifferentValueIsNotTheOrigin(t *testing.T) {
	c := withConf(t, checkerFor(writeKeys(t, weakHost)), map[string]string{
		"90-local.conf": "kernel.dmesg_restrict = 1\n",
	}, "")

	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	f := idsOf(fs)["sysctl.dmesg-restrict"]
	if got := f.Evidence["set-by"]; got != "" {
		t.Errorf("set-by = %q, want none: that file sets 1 and the kernel is running 0", got)
	}
	if !strings.Contains(f.HowToFix, "/etc/sysctl.d") {
		t.Errorf("with no origin the drop-in advice is right:\n%s", f.HowToFix)
	}
}

// No configuration file mentions the key: the value is the kernel's own
// default, a drop-in is the correct remediation, and there is nothing to name.
func TestNoOriginWhenNoFileSetsTheKey(t *testing.T) {
	c := withConf(t, checkerFor(writeKeys(t, weakHost)), map[string]string{
		"90-local.conf": "# nothing relevant\nvm.swappiness = 10\n",
	}, "")

	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if got := idsOf(fs)["sysctl.dmesg-restrict"].Evidence["set-by"]; got != "" {
		t.Errorf("set-by = %q, want none", got)
	}
}

func TestParseAssignment(t *testing.T) {
	for _, tc := range []struct {
		line string
		key  string
		val  int64
		ok   bool
	}{
		{"kernel.dmesg_restrict = 1", "kernel.dmesg_restrict", 1, true},
		{"kernel.dmesg_restrict=0", "kernel.dmesg_restrict", 0, true},
		{"  kernel.dmesg_restrict  =  1  ", "kernel.dmesg_restrict", 1, true},
		// systemd's "apply, but do not complain if it fails" marker is part
		// of the syntax, not of the key.
		{"-kernel.dmesg_restrict = 1", "kernel.dmesg_restrict", 1, true},
		// sysctl.d permits slashes for the same parameter as dots, and a rule
		// keyed on dots would otherwise miss it.
		{"kernel/dmesg_restrict = 1", "kernel.dmesg_restrict", 1, true},
		{"# kernel.dmesg_restrict = 1", "", 0, false},
		{"; kernel.dmesg_restrict = 1", "", 0, false},
		{"", "", 0, false},
		{"kernel.dmesg_restrict", "", 0, false},
		// A glob selects many parameters; rewriting one line of it would
		// change the others too.
		{"net.ipv4.conf.*.accept_redirects = 1", "", 0, false},
		// Not an integer, so no audited rule could ever match it.
		{"kernel.core_pattern = |/usr/share/apport", "", 0, false},
	} {
		key, val, ok := parseAssignment(tc.line)
		if key != tc.key || val != tc.val || ok != tc.ok {
			t.Errorf("parseAssignment(%q) = (%q, %d, %v), want (%q, %d, %v)",
				tc.line, key, val, ok, tc.key, tc.val, tc.ok)
		}
	}
}

// An earlier directory masks a same-named file in a later one rather than
// overriding it: that is how a distribution drop-in is disabled from /etc.
func TestEarlierDirectoryMasksTheSameFileName(t *testing.T) {
	etc, lib := t.TempDir(), t.TempDir()
	for dir, body := range map[string]string{
		etc: "kernel.dmesg_restrict = 0\n",
		lib: "kernel.dmesg_restrict = 1\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, "50-x.conf"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := origins([]string{etc, lib}, "")
	if got["kernel.dmesg_restrict"].Path != filepath.Join(etc, "50-x.conf") {
		t.Errorf("masking failed: %+v", got["kernel.dmesg_restrict"])
	}
}

func TestAvailability(t *testing.T) {
	c := checkerFor(t.TempDir()) // no kernel/ subdir
	if ok, reason := c.Available(context.Background(), platform.Env{}); ok || reason == "" {
		t.Errorf("empty root should be a clean skip with a reason, got ok=%v reason=%q", ok, reason)
	}
	c = checkerFor(writeKeys(t, map[string]string{"kernel.kptr_restrict": "1"}))
	if ok, _ := c.Available(context.Background(), platform.Env{}); !ok {
		t.Error("a readable /proc/sys/kernel should be available")
	}
}

// A non-integer value is unreadable ground, not a guess.
func TestGarbageValueIsPartialNotGuessed(t *testing.T) {
	root := writeKeys(t, map[string]string{"kernel.kptr_restrict": "banana"})
	fs, err := checkerFor(root).Check(context.Background(), platform.Env{})
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want PartialError for an unparseable value, got %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("no finding should be invented from garbage, got %v", fs)
	}
}

// Inside a container the reading is right and the fix is not.
//
// /proc/sys shows the host kernel's value for every knob that is not
// namespaced, so the weakness is real and worth reporting. But the registered
// fix writes /etc/sysctl.d in here, and no amount of `sysctl --system` in a
// container reaches the host kernel — so the file would appear, the fix would
// report success, a checkpoint would be recorded, and the value would never
// move. internal/fix/sysctl.go calls that the worst available outcome and
// declines it for a drop-in that would lose to /usr or /run; this is the same
// refusal for a stronger version of the same reason.
//
// The finding survives. Only the offer of a fix goes.
func TestInAContainerTheFindingStaysAndTheFixDoesNot(t *testing.T) {
	root := writeKeys(t, map[string]string{"kernel.yama.ptrace_scope": "0"})
	c := checkerFor(root)
	c.InContainer = inAContainer

	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}

	var got *model.Finding
	for i := range fs {
		if fs[i].ID == "sysctl.ptrace-scope" {
			got = &fs[i]
		}
	}
	if got == nil {
		t.Fatalf("the host kernel really is weak and the finding must survive, got %v", fs)
	}
	if got.Remediation != model.RemediationManual {
		t.Errorf("remediation = %v, want manual: a fix that writes a file it knows cannot "+
			"take effect is worse than no fix", got.Remediation)
	}
	if got.WhyNoFix == "" {
		t.Error("a finding with no fix and no reason is the gap WhyNoFix exists to close")
	}
	for _, want := range []string{"container", "host"} {
		if !strings.Contains(strings.ToLower(got.HowToFix), want) {
			t.Errorf("how-to-fix does not mention %q, so it does not say where the value "+
				"actually has to be set:\n  %s", want, got.HowToFix)
		}
	}
	if got.Evidence["scanned_from"] == "" {
		t.Error("nothing in the evidence records that this was read from inside a container")
	}
}

// And on a host nothing changes, which is the whole point of the gate being a
// gate rather than a rewrite.
func TestOnAHostTheFixIsStillOffered(t *testing.T) {
	root := writeKeys(t, map[string]string{"kernel.yama.ptrace_scope": "0"})
	fs, err := checkerFor(root).Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.ID != "sysctl.ptrace-scope" {
			continue
		}
		if f.Remediation != model.RemediationAuto {
			t.Errorf("remediation = %v, want auto", f.Remediation)
		}
		if f.WhyNoFix != "" {
			t.Errorf("a fixable finding must carry no WhyNoFix, got %q", f.WhyNoFix)
		}
	}
}
