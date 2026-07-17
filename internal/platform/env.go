package platform

import (
	"bufio"
	"context"
	"os"
	"strings"
)

// PackageManager identifies the host's package manager, used by update
// and install fixes.
type PackageManager string

const (
	PMApt     PackageManager = "apt"
	PMDnf     PackageManager = "dnf"
	PMApk     PackageManager = "apk"
	PMPacman  PackageManager = "pacman"
	PMUnknown PackageManager = ""
)

// ServiceManager identifies the host's init/service manager, used to
// restart services after a fix.
type ServiceManager string

const (
	SMSystemd ServiceManager = "systemd"
	SMOpenRC  ServiceManager = "openrc"
	SMUnknown ServiceManager = ""
)

// Env is the detected host environment passed to every checker. It
// carries the CommandRunner so checkers never construct their own.
type Env struct {
	DistroID       string         // /etc/os-release ID, e.g. "debian", "fedora"
	PackageManager PackageManager
	ServiceManager ServiceManager
	Hostname       string
	Runner         CommandRunner
}

// Detect probes the host once and returns its environment. It is
// deliberately tolerant: unknown fields are left empty rather than
// failing, since a single scan should degrade gracefully on an
// unrecognized distro.
func Detect(ctx context.Context, r CommandRunner) Env {
	env := Env{Runner: r}
	env.DistroID = readOSReleaseID()
	env.PackageManager = detectPackageManager(r)
	env.ServiceManager = detectServiceManager(r)
	if h, err := os.Hostname(); err == nil {
		env.Hostname = h
	}
	return env
}

func readOSReleaseID() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "ID="); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

func detectPackageManager(r CommandRunner) PackageManager {
	// Order matters: check the most specific tools first.
	switch {
	case Has(r, "apt-get"):
		return PMApt
	case Has(r, "dnf"):
		return PMDnf
	case Has(r, "apk"):
		return PMApk
	case Has(r, "pacman"):
		return PMPacman
	default:
		return PMUnknown
	}
}

func detectServiceManager(r CommandRunner) ServiceManager {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return SMSystemd
	}
	if Has(r, "systemctl") {
		return SMSystemd
	}
	if Has(r, "rc-service") {
		return SMOpenRC
	}
	return SMUnknown
}
