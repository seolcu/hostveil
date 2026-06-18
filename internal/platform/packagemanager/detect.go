//go:build linux

// Package packagemanager detects the host's package manager
// and provides read-only commands for the `hardening_updates`
// sub-check. The package is intentionally narrow: it does not
// install, upgrade, or modify the system. It only answers
// "which family?" and "what is the read-only argv for X?".
//
// Detect runs synchronously in the hardening sub-check; the
// orchestrator caches the host-level Detect result in
// HostInfo.Family so that subsequent sub-checks do not re-run
// the detection logic.
package packagemanager

import (
	"os/exec"
	"strings"
)

// Family names match the four supported Linux families.
const (
	FamilyAPT    = "apt"
	FamilyDNF    = "dnf"
	FamilyPacman = "pacman"
	FamilyAPK    = "apk"
)

// PackageManager is the narrow interface used by the
// hardening sub-check. Each implementation answers the same
// three questions for one family.
type PackageManager interface {
	// Name returns the family identifier (apt/dnf/pacman/apk).
	Name() string
	// ListInstalledDryRun returns argv that lists installed
	// packages without mutating the system. Used by the host
	// fingerprint and by an opt-in audit report.
	ListInstalledDryRun() []string
	// SecurityUpdateCountCmd returns argv that prints a
	// newline-delimited list of pending security updates; the
	// scanner counts the lines and maps the count to a
	// severity.
	SecurityUpdateCountCmd() []string
	// ParseSecurityUpdateLines counts the security update
	// entries from a typical output. Implementations are free
	// to over- or under-count; the count is treated as an
	// advisory signal, not a security guarantee.
	ParseSecurityUpdateLines([]string) int
}

// Detect returns the PackageManager for the given binary
// name, or nil if the binary is not one of the four supported
// families. The check is purely lexical: we do not call
// exec.LookPath. Callers that need to assert the binary is
// installed must do so separately (the hardening sub-check
// already does this via exec.LookPath).
func Detect(binary string) PackageManager {
	switch binary {
	case "apt", "apt-get":
		return &aptPM{}
	case "dnf", "yum":
		return &dnfPM{}
	case "pacman":
		return &pacmanPM{}
	case "apk":
		return &apkPM{}
	}
	return nil
}

// DetectInstalled runs Detect over the four family binaries
// in priority order and returns the first one found in PATH.
// Returns nil if none of the four is installed.
func DetectInstalled() PackageManager {
	for _, bin := range []string{"apt", "dnf", "pacman", "apk"} {
		if _, err := exec.LookPath(bin); err == nil {
			return Detect(bin)
		}
	}
	return nil
}

// Name returns the family identifier for the given binary
// or "" if it is not one of the four.
func Name(binary string) string {
	switch binary {
	case "apt", "apt-get":
		return FamilyAPT
	case "dnf", "yum":
		return FamilyDNF
	case "pacman":
		return FamilyPacman
	case "apk":
		return FamilyAPK
	}
	return ""
}

// countSecurityMarkers returns the number of lines that
// contain at least one of the given substrings. Used by
// every family.
func countSecurityMarkers(lines []string, markers ...string) int {
	n := 0
	for _, l := range lines {
		for _, m := range markers {
			if strings.Contains(l, m) {
				n++
				break
			}
		}
	}
	return n
}
