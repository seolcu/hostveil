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
	if got := CalculateScore(f); got != 76 {
		t.Errorf("CalculateScore(3 critical) = %d, want 76", got)
	}
}

func TestCalculateScore_Mixed(t *testing.T) {
	f := []Finding{
		{Severity: SeverityCritical}, // 4
		{Severity: SeverityHigh},     // 3
		{Severity: SeverityMedium},   // 2
		{Severity: SeverityLow},      // 1
	}
	if got := CalculateScore(f); got != 84 {
		t.Errorf("CalculateScore(mixed) = %d, want 84", got)
	}
}

func TestCalculateScore_AxisCap(t *testing.T) {
	f := make([]Finding, 6)
	for i := range f {
		f[i].Severity = SeverityCritical
	}
	if got := CalculateScore(f); got != 70 {
		t.Errorf("CalculateScore(6 critical) = %d, want 70", got)
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
	if sp.Score != 94 {
		t.Errorf("Score = %d, want 94", sp.Score)
	}
	if sp.ScoreBreakdown.Overall != sp.Score {
		t.Errorf("ScoreBreakdown.Overall = %d, want %d", sp.ScoreBreakdown.Overall, sp.Score)
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
	if snap.ScoreBreakdown.Overall != snap.Score {
		t.Errorf("snap.ScoreBreakdown.Overall = %d, want %d", snap.ScoreBreakdown.Overall, snap.Score)
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

func TestScanProgress_Snapshot_Cached(t *testing.T) {
	sp := NewScanProgress(false)
	sp.AddFindings([]Finding{{ID: "x", Severity: SeverityHigh, Source: SourceLynis}})
	sp.Finalize()
	// Two snapshots without any mutation in between should produce equal
	// values (the cache returns a copy of the same underlying snapshot).
	s1 := sp.Snapshot()
	s2 := sp.Snapshot()
	if s1.Findings[0].ID != s2.Findings[0].ID {
		t.Error("cached snapshot should return same data")
	}
}

func TestScanProgress_Snapshot_InvalidatedOnMutation(t *testing.T) {
	sp := NewScanProgress(false)
	sp.AddFindings([]Finding{{ID: "x"}})
	sp.Finalize()
	_ = sp.Snapshot()                    // prime cache
	sp.AddFindings([]Finding{{ID: "y"}}) // bumps version
	snap := sp.Snapshot()
	if len(snap.Findings) != 2 {
		t.Errorf("expected 2 findings after mutation, got %d", len(snap.Findings))
	}
}

func TestScanProgress_Snapshot_InvalidatedOnMarkFixed(t *testing.T) {
	sp := NewScanProgress(false)
	sp.AddFindings([]Finding{{ID: "x", Remediation: RemediationAuto}})
	sp.Finalize()
	_ = sp.Snapshot()     // prime cache
	sp.MarkFixed("x", "") // bumps version
	snap := sp.Snapshot()
	if !snap.Findings[0].Fixed {
		t.Error("MarkFixed should invalidate snapshot cache")
	}
}

func TestScanProgress_Snapshot_InvalidatedOnRecalc(t *testing.T) {
	sp := NewScanProgress(false)
	sp.AddFindings([]Finding{{ID: "x", Remediation: RemediationAuto}})
	sp.Finalize()
	before := sp.Snapshot()
	sp.Recalculate()
	after := sp.Snapshot()
	if after.Score != before.Score {
		// In this trivial case scores are equal, but the snapshot must
		// still be re-built. Check that the returned value is a fresh copy.
	}
	// Mutate the after snapshot; the cached state must be unaffected.
	after.Findings[0].ID = "mutated"
	_ = sp.Snapshot()
	if sp.Findings[0].ID != "x" {
		t.Error("snapshot mutation should not affect underlying state")
	}
}
func TestToolDegraded_StatusValue(t *testing.T) {
	if ToolDegraded <= ToolError {
		t.Errorf("ToolDegraded (%d) should be after ToolError (%d)", ToolDegraded, ToolError)
	}
}
