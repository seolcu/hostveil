package domain

import "testing"

func TestRemediationKindString(t *testing.T) {
	tests := []struct {
		r    RemediationKind
		want string
	}{
		{RemediationManual, "manual"},
		{RemediationAuto, "auto"},
		{RemediationReview, "review"},
		{RemediationKind(99), "unknown"},
	}
	for _, tt := range tests {
		if tt.r.String() != tt.want {
			t.Errorf("String() = %q, want %q", tt.r.String(), tt.want)
		}
	}
}

func TestRemediationKindLabel(t *testing.T) {
	if RemediationAuto.Label() != "Auto Fix" {
		t.Errorf("Auto label = %q, want 'Auto Fix'", RemediationAuto.Label())
	}
	if RemediationManual.Label() != "Manual" {
		t.Errorf("Manual label = %q, want 'Manual'", RemediationManual.Label())
	}
}
