package domain

import "testing"

func TestAxisString(t *testing.T) {
	tests := []struct {
		a    Axis
		want string
	}{
		{AxisSensitiveData, "sensitive_data"},
		{AxisExcessivePermissions, "permissions"},
		{AxisUnnecessaryExposure, "exposure"},
		{AxisUpdateSupplyChain, "supply_chain"},
		{AxisHostHardening, "host_hardening"},
		{Axis(99), "unknown"},
	}
	for _, tt := range tests {
		if tt.a.String() != tt.want {
			t.Errorf("String() = %q, want %q", tt.a.String(), tt.want)
		}
	}
}

func TestAxisLabel(t *testing.T) {
	if AxisSensitiveData.Label() == "" {
		t.Error("Label should not be empty")
	}
	if Axis(99).Label() != "Unknown" {
		t.Error("Unknown axis should return 'Unknown'")
	}
}

func TestAllAxes(t *testing.T) {
	axes := AllAxes()
	if len(axes) != 5 {
		t.Errorf("AllAxes() returned %d axes, want 5", len(axes))
	}
}
