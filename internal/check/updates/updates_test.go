package updates

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

type fakeRunner struct {
	outputs map[string]string
}

func (fakeRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if out, ok := f.outputs[key]; ok {
		return []byte(out), nil
	}
	return nil, errors.New("no output for: " + key)
}

// aptChecker builds a checker whose two file paths point into a temp dir.
// enabled controls whether unattended-upgrades looks configured; reboot
// controls whether the reboot-required flag file exists.
func aptChecker(t *testing.T, enabled, reboot bool) *Checker {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "20auto-upgrades")
	if enabled {
		content := "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
		if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	flag := filepath.Join(dir, "reboot-required")
	if reboot {
		if err := os.WriteFile(flag, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &Checker{AptConfigPath: cfg, RebootRequiredPath: flag}
}

// aptEnv scripts `apt list --upgradable`.
func aptEnv(upgradable string) platform.Env {
	return platform.Env{
		PackageManager: platform.PMApt,
		Runner:         fakeRunner{outputs: map[string]string{"apt list --upgradable": upgradable}},
	}
}

const noUpgrades = "Listing...\n"

func ids(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}

func find(t *testing.T, fs []model.Finding, id string) model.Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no %s in %v", id, ids(fs))
	return model.Finding{}
}

func TestAptDisabled(t *testing.T) {
	fs, err := aptChecker(t, false, false).Check(context.Background(), aptEnv(noUpgrades))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].ID != "updates.disabled" {
		t.Errorf("expected one updates.disabled finding, got %v", ids(fs))
	}
}

func TestAptEnabled(t *testing.T) {
	fs, err := aptChecker(t, true, false).Check(context.Background(), aptEnv(noUpgrades))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a fully patched host with unattended-upgrades on is clean, got %v", ids(fs))
	}
}

// The case the axis used to score 100 for: the mechanism is on, so the old
// check was satisfied, while the machine still runs the vulnerable code it
// already downloaded the fix for.
func TestEnabledButRebootPendingIsNotClean(t *testing.T) {
	fs, err := aptChecker(t, true, true).Check(context.Background(), aptEnv(noUpgrades))
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, fs, "updates.reboot-required")
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if len(fs) != 1 {
		t.Errorf("want only the reboot finding, got %v", ids(fs))
	}
}

// Likewise: unattended-upgrades enabled and a backlog it never applied.
func TestEnabledButSecurityUpdatesPendingIsNotClean(t *testing.T) {
	upgradable := `Listing...
libssl3/jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
linux-libc-dev/jammy-security 5.15.0-91.101 amd64 [upgradable from: 5.15.0-88.98]
vim/jammy-updates 2:8.2.3995-1ubuntu2.15 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.13]
`
	fs, err := aptChecker(t, true, false).Check(context.Background(), aptEnv(upgradable))
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, fs, "updates.pending-security")
	// vim comes from -updates, not -security: a host pinned behind on
	// feature updates is a maintenance choice, not a vulnerability.
	if f.Evidence["pending"] != "2" {
		t.Errorf("pending = %q, want 2 (only the -security rows)", f.Evidence["pending"])
	}
	if f.Severity != model.SeverityMedium {
		t.Errorf("severity = %v, want medium for a small backlog", f.Severity)
	}
}

// A large backlog means automatic updates are configured but failing, which
// is worse than merely switched off — the operator believes it is handled.
func TestLargeSecurityBacklogIsHigh(t *testing.T) {
	var b strings.Builder
	b.WriteString("Listing...\n")
	for i := 0; i < 12; i++ {
		b.WriteString("pkg" + strings.Repeat("x", i) + "/jammy-security 1.2 amd64 [upgradable from: 1.1]\n")
	}
	fs, err := aptChecker(t, true, false).Check(context.Background(), aptEnv(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if f := find(t, fs, "updates.pending-security"); f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high for a 12-package backlog", f.Severity)
	}
}

// Not being able to list updates is a blind spot, not a clean result. The
// mechanism half of the domain was still covered, so this is Degraded.
func TestAptUnreadableUpgradeListIsPartial(t *testing.T) {
	env := platform.Env{PackageManager: platform.PMApt, Runner: fakeRunner{}}
	fs, err := aptChecker(t, false, false).Check(context.Background(), env)

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError so the axis reports Degraded, got %v", err)
	}
	// What we did learn is still reported.
	find(t, fs, "updates.disabled")
}

func dnfEnv(outputs map[string]string) platform.Env {
	return platform.Env{PackageManager: platform.PMDnf, Runner: fakeRunner{outputs: outputs}}
}

func dnfClean() map[string]string {
	return map[string]string{
		"systemctl is-enabled dnf-automatic.timer": "enabled\n",
		"needs-restarting -r":                      "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n",
		"dnf -q updateinfo list security":          "",
	}
}

func TestDnfEnabled(t *testing.T) {
	fs, err := New().Check(context.Background(), dnfEnv(dnfClean()))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("enabled dnf-automatic on a patched host is clean, got %v", ids(fs))
	}
}

func TestDnfDisabled(t *testing.T) {
	out := dnfClean()
	out["systemctl is-enabled dnf-automatic.timer"] = "disabled\n"
	fs, err := New().Check(context.Background(), dnfEnv(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].ID != "updates.disabled" {
		t.Errorf("expected one updates.disabled finding, got %v", ids(fs))
	}
}

// `needs-restarting -r` exits NON-zero when a reboot is required, so reading
// its exit status would inverte the answer. The text is the signal.
func TestDnfRebootRequiredReadFromText(t *testing.T) {
	out := dnfClean()
	out["needs-restarting -r"] = "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n"
	fs, err := New().Check(context.Background(), dnfEnv(out))
	if err != nil {
		t.Fatal(err)
	}
	find(t, fs, "updates.reboot-required")
}

func TestDnfSecurityAdvisoriesCounted(t *testing.T) {
	out := dnfClean()
	out["dnf -q updateinfo list security"] = `FEDORA-2026-aaaa Important/Sec. openssl-3.2.1-1.fc41.x86_64
FEDORA-2026-bbbb Moderate/Sec.  curl-8.6.0-1.fc41.x86_64
`
	fs, err := New().Check(context.Background(), dnfEnv(out))
	if err != nil {
		t.Fatal(err)
	}
	if f := find(t, fs, "updates.pending-security"); f.Evidence["pending"] != "2" {
		t.Errorf("pending = %q, want 2", f.Evidence["pending"])
	}
}

// An answer matching neither phrase means the command did not tell us, which
// must not be read as "no reboot needed".
func TestDnfUnrecognizedRebootAnswerIsPartial(t *testing.T) {
	out := dnfClean()
	out["needs-restarting -r"] = "some future wording nobody anticipated\n"
	_, err := New().Check(context.Background(), dnfEnv(out))

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError rather than a silent clean, got %v", err)
	}
}

func TestClassifyNeedsRestarting(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want rebootState
	}{
		{"Reboot should not be necessary.", rebootNotNeeded},
		{"Reboot is required to fully utilize these updates.", rebootRequired},
		{"Reboot is probably required to fully utilize these updates.", rebootRequired},
		{"", rebootUnknown},
		{"command not found", rebootUnknown},
	} {
		if got := classifyNeedsRestarting(tc.out); got != tc.want {
			t.Errorf("classifyNeedsRestarting(%q) = %v, want %v", tc.out, got, tc.want)
		}
	}
}

// TestAvailableByPackageManager pins the distinction between "looked and
// found nothing" and "could not look". Only apt and dnf have an
// auto-update mechanism this checker knows how to verify; on anything else
// it must skip so the axis is excluded as N/A, never scored as clean.
func TestAvailableByPackageManager(t *testing.T) {
	for _, tc := range []struct {
		pm      platform.PackageManager
		wantOK  bool
		wantSub string
	}{
		{platform.PMApt, true, ""},
		{platform.PMDnf, true, ""},
		{platform.PMApk, false, "apk"},
		{platform.PMPacman, false, "pacman"},
		{platform.PMUnknown, false, "no recognized package manager"},
	} {
		ok, reason := New().Available(context.Background(), platform.Env{PackageManager: tc.pm})
		if ok != tc.wantOK {
			t.Errorf("%q: Available = %v, want %v", tc.pm, ok, tc.wantOK)
		}
		if ok && reason != "" {
			t.Errorf("%q: available checker gave a skip reason %q", tc.pm, reason)
		}
		if !ok && !strings.Contains(reason, tc.wantSub) {
			t.Errorf("%q: reason %q does not mention %q", tc.pm, reason, tc.wantSub)
		}
	}
}

// TestCheckRejectsUnsupportedPackageManager guards the invariant from the
// other side: if Available ever stops filtering, Check must error (→ the
// axis is excluded) rather than return nil findings (→ scored 100).
func TestCheckRejectsUnsupportedPackageManager(t *testing.T) {
	for _, pm := range []platform.PackageManager{platform.PMApk, platform.PMPacman, platform.PMUnknown} {
		fs, err := New().Check(context.Background(), platform.Env{PackageManager: pm})
		if err == nil {
			t.Errorf("%q: Check returned nil error — a silent clean result", pm)
		}
		if len(fs) != 0 {
			t.Errorf("%q: Check returned findings %v alongside the error", pm, fs)
		}
	}
}
