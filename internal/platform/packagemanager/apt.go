//go:build linux

package packagemanager

type aptPM struct{}

func (aptPM) Name() string { return FamilyAPT }

func (aptPM) ListInstalledDryRun() []string {
	return []string{"apt", "list", "--installed"}
}

func (aptPM) SecurityUpdateCountCmd() []string {
	return []string{"apt", "list", "--upgradable"}
}

func (aptPM) ParseSecurityUpdateLines(lines []string) int {
	return countSecurityMarkers(lines, "-security", "-updates")
}
