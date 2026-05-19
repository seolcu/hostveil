package domain

import "testing"

func TestFindingIsFixable(t *testing.T) {
	tests := []struct {
		r    RemediationKind
		want bool
	}{
		{RemediationManual, false},
		{RemediationAuto, true},
		{RemediationReview, true},
	}
	for _, tt := range tests {
		f := Finding{ID: "test", Remediation: tt.r}
		got := f.IsFixable()
		if got != tt.want {
			t.Errorf("IsFixable() with %v = %v, want %v", tt.r, got, tt.want)
		}
	}
}

func TestTotalFindings(t *testing.T) {
	r := &ScanResult{
		Findings: []Finding{
			{ID: "a"}, {ID: "b"}, {ID: "c"},
		},
	}
	if r.TotalFindings() != 3 {
		t.Errorf("TotalFindings() = %d, want 3", r.TotalFindings())
	}
}

func TestFindingsBySeverity(t *testing.T) {
	r := &ScanResult{
		Findings: []Finding{
			{ID: "a", Severity: SeverityCritical},
			{ID: "b", Severity: SeverityHigh},
			{ID: "c", Severity: SeverityCritical},
			{ID: "d", Severity: SeverityLow},
		},
	}
	if r.FindingsBySeverity(SeverityCritical) != 2 {
		t.Errorf("critical count = %d, want 2", r.FindingsBySeverity(SeverityCritical))
	}
	if r.FindingsBySeverity(SeverityMedium) != 0 {
		t.Errorf("medium count = %d, want 0", r.FindingsBySeverity(SeverityMedium))
	}
}
