package domain

import "testing"

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{Severity(99), "unknown"},
	}
	for _, tt := range tests {
		if tt.s.String() != tt.want {
			t.Errorf("String() = %q, want %q", tt.s.String(), tt.want)
		}
	}
}

func TestSeverityColor(t *testing.T) {
	if SeverityCritical.Color() == "" {
		t.Error("Critical color should not be empty")
	}
	if SeverityHigh.Color() == SeverityLow.Color() {
		t.Error("High and Low should have different colors")
	}
}
