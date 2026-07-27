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

func checkerFor(root string) *Checker {
	c := New()
	c.Root = root
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
		if f.Remediation != model.RemediationManual {
			t.Errorf("%s: remediation = %v, want Manual", f.ID, f.Remediation)
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
