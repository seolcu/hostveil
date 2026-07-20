package updates

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestAptDisabled(t *testing.T) {
	c := &Checker{AptConfigPath: filepath.Join(t.TempDir(), "missing")}
	fs, err := c.Check(context.Background(), platform.Env{PackageManager: platform.PMApt})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].ID != "updates.disabled" {
		t.Errorf("expected one updates.disabled finding, got %v", fs)
	}
}

func TestAptEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "20auto-upgrades")
	content := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Checker{AptConfigPath: path}
	fs, err := c.Check(context.Background(), platform.Env{PackageManager: platform.PMApt})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("enabled unattended-upgrades should yield no finding, got %v", fs)
	}
}

func TestDnfEnabled(t *testing.T) {
	r := fakeRunner{outputs: map[string]string{"systemctl is-enabled dnf-automatic.timer": "enabled\n"}}
	fs, err := New().Check(context.Background(), platform.Env{PackageManager: platform.PMDnf, Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("enabled dnf-automatic should yield no finding, got %v", fs)
	}
}

func TestDnfDisabled(t *testing.T) {
	r := fakeRunner{outputs: map[string]string{"systemctl is-enabled dnf-automatic.timer": "disabled\n"}}
	fs, err := New().Check(context.Background(), platform.Env{PackageManager: platform.PMDnf, Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Errorf("disabled dnf-automatic should yield one finding, got %v", fs)
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
