//go:build linux

package packagemanager

import "strings"

type pacmanPM struct{}

func (pacmanPM) Name() string { return FamilyPacman }

func (pacmanPM) ListInstalledDryRun() []string {
	return []string{"pacman", "-Q"}
}

func (pacmanPM) SecurityUpdateCountCmd() []string {
	return []string{"pacman", "-Qu"}
}

func (pacmanPM) ParseSecurityUpdateLines(lines []string) int {
	// `pacman -Qu` prints one package per line in the form
	// `<name> <old> -> <new>`. We treat any line that mentions
	// "security" in the upgrade message as a security update;
	// Arch's security-tracker tags upgrades via the package
	// version, so we conservatively count all upgrades.
	n := 0
	for _, l := range lines {
		if strings.Contains(l, "->") {
			n++
		}
	}
	return n
}
