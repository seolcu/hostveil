package platform

import (
	"bufio"
	"context"
	"io"
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
	DistroID       string // /etc/os-release ID, e.g. "debian", "fedora"
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

// osReleasePath is where the distro identity is read from. It is a variable
// so the parsing can be tested against real fixtures — every distro spells
// this file slightly differently, and a parser for it that has only ever
// been run against the machine it was written on is a guess.
var osReleasePath = "/etc/os-release"

func readOSReleaseID() string {
	f, err := os.Open(osReleasePath)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	return parseOSReleaseID(f)
}

// parseOSReleaseID pulls ID= out of an os-release file.
//
// The prefix match must be exact: ID_LIKE= sits right beside it in every
// Ubuntu and Rocky os-release, and a prefix test that accepted it would
// report Ubuntu as Debian. Values may be bare, single-quoted, or
// double-quoted — os-release permits all three and distros use all three.
func parseOSReleaseID(r io.Reader) string {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
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

// systemdRunDir exists only when systemd is the running init, which is a
// stronger signal than systemctl being on PATH: a container image can carry
// the binary without systemd ever being pid 1.
var systemdRunDir = "/run/systemd/system"

func detectServiceManager(r CommandRunner) ServiceManager {
	if _, err := os.Stat(systemdRunDir); err == nil {
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
