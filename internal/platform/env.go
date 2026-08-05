package platform

import (
	"bufio"
	"context"
	"io"
	"os"
	"runtime"
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

	// OS is the host's operating system, from runtime.GOOS. It is the one
	// place in hostveil that asks, and it exists so a checker can tell
	// "I looked and found nothing" apart from "this is not a host I can
	// audit" — see AuditableOS.
	OS string
}

// LinuxOS is the only operating system hostveil's checkers can audit.
const LinuxOS = "linux"

// AuditableOS reports whether the host is one the checkers can draw
// conclusions about, and why not when it is not.
//
// hostveil builds and runs on darwin — goreleaser publishes those archives —
// and every detection rule in it is about Linux. Most domains discover that
// on their own and skip cleanly: there is no /proc/sys, no systemd, no
// apt-get, no ss. Three did not, and each turned "I could not look" into an
// answer, which is the one thing this codebase says a checker must never do:
//
//   - firewall probes ufw, firewall-cmd, nft and iptables. None is installed
//     on macOS, no probe fails, and the absence of a failure was read as the
//     absence of a firewall — a guaranteed `firewall.inactive` at the top
//     severity, on every Mac, whose actual packet filter is pf and whose
//     application firewall is socketfilterfw. Neither is probed anywhere.
//   - accounts reads /etc/passwd, which macOS ships as a stub because the
//     real account database is Open Directory, then advises re-running with
//     sudo to read an /etc/shadow that does not exist and never will.
//   - agent enumerates home directories out of that same /etc/passwd, keeping
//     uid 0 and 1000..65533. macOS user accounts start at 501, so it finds
//     only /var/root and reports "no agent runtime found" without ever having
//     looked at /Users — the exact confusion that package's doc comment says
//     it exists to prevent.
//
// The result was not an N/A score. firewall and fileperms are unconditionally
// available, so a Mac produced a plausible number built on a false finding.
//
// This is a statement about the operating system and not about any tool, so
// it lives here with the rest of the "what host is this" questions rather
// than in three checkers making the same call three ways.
func AuditableOS() (bool, string) { return auditableOS(runtime.GOOS) }

// auditableOS is the rule itself, taking the operating system as an argument
// so it can be tested for the platforms this build is not running on. The
// exported wrapper reads runtime.GOOS directly rather than Env.OS, because a
// checker that forgot to populate the field would then audit a Mac as Linux —
// and the whole point of this is that the failure must not be silent.
func auditableOS(goos string) (bool, string) {
	if goos == LinuxOS {
		return true, ""
	}
	return false, "hostveil audits Linux hosts; this is " + goos
}

// Detect probes the host once and returns its environment. It is
// deliberately tolerant: unknown fields are left empty rather than
// failing, since a single scan should degrade gracefully on an
// unrecognized distro.
func Detect(ctx context.Context, r CommandRunner) Env {
	env := Env{Runner: r, OS: runtime.GOOS}
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
