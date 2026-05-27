package domain

import (
	"testing"
)

func TestCalculateScore_Empty(t *testing.T) {
	if got := CalculateScore(nil); got != 100 {
		t.Errorf("CalculateScore(nil) = %d, want 100", got)
	}
}

func TestCalculateScore_AllCritical(t *testing.T) {
	f := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
	}
	if got := CalculateScore(f); got != 40 {
		t.Errorf("CalculateScore(3 critical) = %d, want 40 (100-60)", got)
	}
}

func TestCalculateScore_Mixed(t *testing.T) {
	f := []Finding{
		{Severity: SeverityCritical}, // 4
		{Severity: SeverityHigh},     // 3
		{Severity: SeverityMedium},   // 2
		{Severity: SeverityLow},      // 1
	}
	// total = 10, score = 100 - 10*5 = 50
	if got := CalculateScore(f); got != 50 {
		t.Errorf("CalculateScore(mixed) = %d, want 50", got)
	}
}

func TestCalculateScore_Floor(t *testing.T) {
	f := make([]Finding, 6)
	for i := range f {
		f[i].Severity = SeverityCritical
	}
	if got := CalculateScore(f); got != 0 {
		t.Errorf("CalculateScore(6 critical) = %d, want 0", got)
	}
}

func TestNewScanProgress_IncludesUpdate(t *testing.T) {
	sp := NewScanProgress(false)
	if _, ok := sp.Tools["update"]; !ok {
		t.Error("NewScanProgress(false) should include update tool")
	}
	if _, ok := sp.Tools["trivy"]; !ok {
		t.Error("NewScanProgress should include trivy tool")
	}
}

func TestNewScanProgress_NoUpdate(t *testing.T) {
	sp := NewScanProgress(true)
	if _, ok := sp.Tools["update"]; ok {
		t.Error("NewScanProgress(true) should not include update tool")
	}
}

func TestScanProgress_SetToolStatus(t *testing.T) {
	sp := NewScanProgress(false)
	sp.SetToolStatus("trivy", ToolRunning, "scanning...")
	state := sp.ToolState("trivy")
	if state.Status != ToolRunning || state.Message != "scanning..." {
		t.Errorf("ToolState = %+v, want {Running, scanning...}", state)
	}
}

func TestScanProgress_ToolState_NotFound(t *testing.T) {
	sp := NewScanProgress(false)
	state := sp.ToolState("nonexistent")
	if state.Message != "" {
		t.Errorf("ToolState for missing tool should be empty")
	}
}

func TestScanProgress_AllToolsDone(t *testing.T) {
	sp := NewScanProgress(false)
	if sp.AllToolsDone() {
		t.Error("fresh ScanProgress should not have all tools done")
	}
	sp.SetToolStatus("update", ToolDone, "")
	sp.SetToolStatus("trivy", ToolDone, "")
	sp.SetToolStatus("lynis", ToolDone, "")
	if !sp.AllToolsDone() {
		t.Error("all tools done should return true")
	}
}

func TestScanProgress_AddFindings(t *testing.T) {
	sp := NewScanProgress(false)
	sp.AddFindings([]Finding{{ID: "a"}})
	sp.AddFindings([]Finding{{ID: "b"}})
	if len(sp.Findings) != 2 {
		t.Errorf("Findings = %d, want 2", len(sp.Findings))
	}
}

func TestScanProgress_Finalize(t *testing.T) {
	sp := NewScanProgress(false)
	sp.AddFindings([]Finding{
		{Severity: SeverityHigh},
		{Severity: SeverityLow},
	})
	sp.Finalize()
	if sp.Phase != "complete" {
		t.Errorf("Phase = %s, want complete", sp.Phase)
	}
	if sp.Score != 80 {
		t.Errorf("Score = %d, want 80", sp.Score)
	}
	if sp.Grade != "B" {
		t.Errorf("Grade = %s, want B", sp.Grade)
	}
}

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score uint8
		want  string
	}{
		{100, "A"}, {95, "A"}, {90, "A"},
		{89, "B"}, {75, "B"}, {70, "B"},
		{69, "C"}, {55, "C"}, {50, "C"},
		{49, "D"}, {35, "D"}, {30, "D"},
		{29, "F"}, {10, "F"}, {0, "F"},
	}
	for _, tt := range tests {
		if got := GradeFromScore(tt.score); got != tt.want {
			t.Errorf("GradeFromScore(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestScanProgress_SetUpdateAvailable(t *testing.T) {
	sp := NewScanProgress(false)
	sp.SetUpdateAvailable("v2.0.1")
	if sp.UpdateAvailable != "v2.0.1" {
		t.Errorf("UpdateAvailable = %s, want v2.0.1", sp.UpdateAvailable)
	}
}

func TestScanProgress_Snapshot_Consistency(t *testing.T) {
	sp := NewScanProgress(false)
	sp.AddFindings([]Finding{{ID: "x"}})
	sp.Finalize()
	snap := sp.Snapshot()
	if snap.Phase != "complete" {
		t.Errorf("snap.Phase = %s, want complete", snap.Phase)
	}
	if len(snap.Findings) != 1 {
		t.Errorf("snap.Findings = %d, want 1", len(snap.Findings))
	}
	if _, ok := snap.Tools["trivy"]; !ok {
		t.Error("snap.Tools missing trivy")
	}
}

func TestScanProgress_Snapshot_Immutable(t *testing.T) {
	sp := NewScanProgress(false)
	sp.AddFindings([]Finding{{ID: "original"}})
	snap := sp.Snapshot()
	snap.Findings[0].ID = "mutated"
	if sp.Findings[0].ID != "original" {
		t.Error("Snapshot should not mutate original")
	}
}

func TestToolDegraded_StatusValue(t *testing.T) {
	if ToolDegraded <= ToolError {
		t.Errorf("ToolDegraded (%d) should be after ToolError (%d)", ToolDegraded, ToolError)
	}
}
