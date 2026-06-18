// Package platform reports the runtime platform and provides Linux-only
// helpers (sysctl, Docker socket, package manager, privilege
// elevation). hostveil refuses to start on non-Linux (FR-022).
package platform

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

// ErrUnsupportedPlatform is returned by Detect on non-Linux systems.
var ErrUnsupportedPlatform = errors.New("unsupported platform")

// OSInfo describes the host's operating system.
type OSInfo struct {
	Family  string // debian | rhel | arch | alpine | other
	Version string
	Kernel  string
	Arch    string
}

// Detect returns the OSInfo for the current host. On non-Linux it
// returns ErrUnsupportedPlatform.
func Detect() (OSInfo, error) {
	if runtime.GOOS != "linux" {
		return OSInfo{}, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
	}
	info := OSInfo{
		Kernel: readKernel(),
		Arch:   runtime.GOARCH,
	}
	info.Family, info.Version = readOSRelease()
	return info, nil
}

func readKernel() string {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		s := string(data)
		if len(s) > 0 && s[len(s)-1] == '\n' {
			s = s[:len(s)-1]
		}
		return s
	}
	return runtime.GOOS
}

func readOSRelease() (family, version string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "other", ""
	}
	var id, ver string
	for _, line := range splitLines(string(data)) {
		if k, v, ok := splitEq(line); ok {
			switch k {
			case "ID":
				id = v
			case "VERSION_ID":
				ver = v
			}
		}
	}
	switch id {
	case "debian", "ubuntu", "linuxmint", "pop":
		family = "debian"
	case "rhel", "centos", "fedora", "rocky", "almalinux", "amzn":
		family = "rhel"
	case "arch", "manjaro", "endeavouros":
		family = "arch"
	case "alpine":
		family = "alpine"
	default:
		family = "other"
	}
	return family, ver
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func splitEq(line string) (string, string, bool) {
	if len(line) == 0 || line[0] == '#' {
		return "", "", false
	}
	for i, c := range line {
		if c == '=' {
			return line[:i], trimQuotes(line[i+1:]), true
		}
	}
	return "", "", false
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
