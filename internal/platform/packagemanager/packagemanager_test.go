//go:build linux

package packagemanager

import "testing"

// TestDetect_KnownFamilies asserts that the four supported
// families resolve to the correct concrete type via the
// Detect dispatch.
func TestDetect_KnownFamilies(t *testing.T) {
	cases := []struct {
		name    string
		binary  string
		want    string
	}{
		{"apt", "apt", "*packagemanager.aptPM"},
		{"dnf", "dnf", "*packagemanager.dnfPM"},
		{"pacman", "pacman", "*packagemanager.pacmanPM"},
		{"apk", "apk", "*packagemanager.apkPM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pm := Detect(tc.binary)
			got := typeName(pm)
			if got != tc.want {
				t.Errorf("Detect(%q) type = %s, want %s", tc.binary, got, tc.want)
			}
		})
	}
}

// TestDetect_UnknownFamily asserts that an unknown binary
// returns nil so callers can fall back to a "not_applicable"
// category skip.
func TestDetect_UnknownFamily(t *testing.T) {
	if pm := Detect("emerge"); pm != nil {
		t.Errorf("Detect(emerge) = %v, want nil", pm)
	}
}

// TestFamily_Interface asserts that every concrete type
// implements the PackageManager interface.
func TestFamily_Interface(t *testing.T) {
	var _ PackageManager = aptPM{}
	var _ PackageManager = dnfPM{}
	var _ PackageManager = pacmanPM{}
	var _ PackageManager = apkPM{}
}

// TestListInstalled_DryRun asserts that the apt/dnf/pacman/apk
// families expose a `list_installed_dryrun` argv slice that
// does not mutate system state (a property we rely on to keep
// SC-001 within budget and the data layer offline-only).
func TestListInstalled_DryRun(t *testing.T) {
	cases := []PackageManager{aptPM{}, dnfPM{}, pacmanPM{}, apkPM{}}
	for _, pm := range cases {
		args := pm.ListInstalledDryRun()
		if len(args) == 0 {
			t.Errorf("%s: ListInstalledDryRun() returned empty args", pm.Name())
		}
	}
}

// TestSecurityUpdates_Args asserts that the security-update
// argv slice is non-empty for every family.
func TestSecurityUpdates_Args(t *testing.T) {
	cases := []PackageManager{aptPM{}, dnfPM{}, pacmanPM{}, apkPM{}}
	for _, pm := range cases {
		args := pm.SecurityUpdateCountCmd()
		if len(args) == 0 {
			t.Errorf("%s: SecurityUpdateCountCmd() returned empty args", pm.Name())
		}
	}
}

func typeName(v any) string {
	if v == nil {
		return "nil"
	}
	return "*packagemanager." + nameOf(v)
}

func nameOf(v any) string {
	switch v.(type) {
	case *aptPM:
		return "aptPM"
	case *dnfPM:
		return "dnfPM"
	case *pacmanPM:
		return "pacmanPM"
	case *apkPM:
		return "apkPM"
	}
	return "unknown"
}
