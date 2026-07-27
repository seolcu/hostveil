package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Host detection had no test at all, and it decides which distro-specific
// branch every other checker takes: the updates checker skips itself
// entirely on PMUnknown, and reads a completely different set of files on
// apt than on dnf. Getting this wrong does not produce a wrong finding, it
// produces a silently skipped domain.

// pmRunner reports a fixed set of binaries as present.
type pmRunner struct{ present map[string]bool }

func (p pmRunner) LookPath(name string) (string, error) {
	if p.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found: " + name)
}

func (pmRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("not used")
}

func have(names ...string) pmRunner {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return pmRunner{present: m}
}

// The os-release files here are copied from the distros they name. ID_LIKE
// sits next to ID on half of them, which is the trap: a prefix test that
// accepted it reports Ubuntu as Debian and Rocky as Fedora.
func TestParseOSReleaseID(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"debian", "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\n", "debian"},
		{
			"ubuntu carries ID_LIKE=debian",
			"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n",
			"ubuntu",
		},
		{
			"rocky carries ID_LIKE=\"rhel centos fedora\"",
			"NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
			"rocky",
		},
		{"fedora", "NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\n", "fedora"},
		{"alpine", "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.21.0\n", "alpine"},
		{"single quotes are permitted by the spec", "ID='arch'\n", "arch"},
		{"leading whitespace", "  ID=debian\n", "debian"},
		{"ID_LIKE alone is not an ID", "NAME=\"Weird\"\nID_LIKE=debian\n", ""},
		{"no ID at all", "NAME=\"Mystery\"\n", ""},
		{"empty file", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseOSReleaseID(strings.NewReader(tc.body)); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A host with no readable os-release is not an error — Detect is documented
// as tolerant, and an unknown distro must degrade rather than fail the scan.
func TestAMissingOSReleaseIsEmptyNotFatal(t *testing.T) {
	orig := osReleasePath
	osReleasePath = filepath.Join(t.TempDir(), "nope")
	t.Cleanup(func() { osReleasePath = orig })

	if got := readOSReleaseID(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// Order is load-bearing: Debian and Ubuntu ship both apt-get and (on some
// images) other tools, so the most specific has to win. Getting this
// backwards sends the updates checker down the wrong branch entirely.
func TestDetectPackageManager(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    pmRunner
		want PackageManager
	}{
		{"debian", have("apt-get"), PMApt},
		{"fedora", have("dnf"), PMDnf},
		{"alpine", have("apk"), PMApk},
		{"arch", have("pacman"), PMPacman},
		{"nothing recognisable", have(), PMUnknown},
		{"apt wins over a stray dnf", have("apt-get", "dnf"), PMApt},
		{"dnf wins over a stray apk", have("dnf", "apk"), PMDnf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectPackageManager(tc.r); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The running-init directory is a stronger signal than the binary being on
// PATH: a container image can ship systemctl without systemd ever being
// pid 1, and telling a user to `systemctl enable` something there is advice
// that cannot work.
func TestDetectServiceManager(t *testing.T) {
	realDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(realDir, "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		runDir string
		r      pmRunner
		want   ServiceManager
	}{
		{"systemd is pid 1", filepath.Join(realDir, "systemd", "system"), have(), SMSystemd},
		{"systemctl on PATH without the run dir", filepath.Join(realDir, "absent"), have("systemctl"), SMSystemd},
		{"openrc", filepath.Join(realDir, "absent"), have("rc-service"), SMOpenRC},
		{"neither", filepath.Join(realDir, "absent"), have(), SMUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := systemdRunDir
			systemdRunDir = tc.runDir
			t.Cleanup(func() { systemdRunDir = orig })

			if got := detectServiceManager(tc.r); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Detect must fill in what it can and leave the rest empty rather than
// failing, and it must carry the runner through — checkers construct no
// runner of their own, so an Env without one is a nil dereference waiting
// in every domain.
func TestDetectIsTolerantAndCarriesTheRunner(t *testing.T) {
	orig := osReleasePath
	osReleasePath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { osReleasePath = orig })

	r := have("apt-get")
	env := Detect(context.Background(), r)

	if env.Runner == nil {
		t.Error("Env must carry the runner it was built with")
	}
	if env.DistroID != "" {
		t.Errorf("an unreadable os-release should leave DistroID empty, got %q", env.DistroID)
	}
	if env.PackageManager != PMApt {
		t.Errorf("PackageManager = %q, want apt", env.PackageManager)
	}
	if env.Hostname == "" {
		t.Error("Hostname should be filled in")
	}
}
