//go:build linux

package packagemanager

type apkPM struct{}

func (apkPM) Name() string { return FamilyAPK }

func (apkPM) ListInstalledDryRun() []string {
	return []string{"apk", "list", "--installed"}
}

func (apkPM) SecurityUpdateCountCmd() []string {
	return []string{"apk", "version", "-l", "<"}
}

func (apkPM) ParseSecurityUpdateLines(lines []string) int {
	// `apk version -l <` prints one package per line in the
	// form `<name>-<old> -> <new>`. We count lines containing
	// the upgrade arrow.
	return countSecurityMarkers(lines, "->")
}
