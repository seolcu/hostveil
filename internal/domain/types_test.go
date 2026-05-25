package domain

import (
	"testing"
)

func TestSeverity_String(t *testing.T) {
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
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestSource_String(t *testing.T) {
	tests := []struct {
		s    Source
		want string
	}{
		{SourceTrivy, "trivy"},
		{SourceLynis, "lynis"},
		{Source(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Source(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestRemediationKind_IsFixable(t *testing.T) {
	tests := []struct {
		r    RemediationKind
		want bool
	}{
		{RemediationAuto, true},
		{RemediationReview, true},
		{RemediationUnavailable, false},
		{RemediationManual, false},
	}
	for _, tt := range tests {
		if got := tt.r.IsFixable(); got != tt.want {
			t.Errorf("RemediationKind(%d).IsFixable() = %v, want %v", tt.r, got, tt.want)
		}
	}
}

func TestRemediationKind_String(t *testing.T) {
	tests := []struct {
		r    RemediationKind
		want string
	}{
		{RemediationAuto, "auto"},
		{RemediationReview, "review"},
		{RemediationUnavailable, "unavailable"},
		{RemediationManual, "manual"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("RemediationKind(%d).String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestRemediationKind_Label(t *testing.T) {
	tests := []struct {
		r    RemediationKind
		want string
	}{
		{RemediationAuto, "Auto-fix"},
		{RemediationReview, "Review"},
		{RemediationUnavailable, "Unavailable"},
		{RemediationManual, "Manual"},
	}
	for _, tt := range tests {
		if got := tt.r.Label(); got != tt.want {
			t.Errorf("RemediationKind(%d).Label() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestFinding_IsFixable(t *testing.T) {
	f := &Finding{Remediation: RemediationAuto}
	if !f.IsFixable() {
		t.Error("Auto fix should be fixable")
	}
	f.Remediation = RemediationUnavailable
	if f.IsFixable() {
		t.Error("Unavailable should not be fixable")
	}
}

func TestScanResult_TotalFindings(t *testing.T) {
	r := &ScanResult{Findings: []Finding{{}, {}}}
	if got := r.TotalFindings(); got != 2 {
		t.Errorf("TotalFindings() = %d, want 2", got)
	}
}
