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

func TestUnknownPackageManagerNoFinding(t *testing.T) {
	fs, err := New().Check(context.Background(), platform.Env{PackageManager: platform.PMUnknown})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("unknown package manager should yield no finding, got %v", fs)
	}
}
