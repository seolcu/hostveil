//go:build linux

package packagemanager

import "strings"

type dnfPM struct{}

func (dnfPM) Name() string { return FamilyDNF }

func (dnfPM) ListInstalledDryRun() []string {
	return []string{"dnf", "list", "installed"}
}

func (dnfPM) SecurityUpdateCountCmd() []string {
	return []string{"dnf", "check-update", "--security"}
}

func (dnfPM) ParseSecurityUpdateLines(lines []string) int {
	// `dnf check-update --security` exit code 100 means updates
	// are available; the output lists one package per line.
	// We count non-empty, non-header lines.
	n := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// Skip the header line "Last metadata expiration check: ..."
		if strings.HasPrefix(l, "Last metadata") || strings.HasPrefix(l, "Loaded plugins") {
			continue
		}
		// Skip the legend at the bottom of the table.
		if strings.HasPrefix(l, "Obsoleting") || strings.HasPrefix(l, "Upgrade") {
			continue
		}
		n++
	}
	return n
}
