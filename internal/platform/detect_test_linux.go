//go:build linux

package platform

import "testing"

func TestDetect_Linux(t *testing.T) {
	info, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if info.Arch == "" {
		t.Errorf("Detect() Arch empty")
	}
	switch info.Family {
	case "debian", "rhel", "arch", "alpine", "other":
	default:
		t.Errorf("Detect() Family = %q, want one of debian/rhel/arch/alpine/other", info.Family)
	}
}
