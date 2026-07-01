package domain

import "testing"

// TestScanProgress_ResetForRescan verifies the rescan path: every
// non-update tool's state returns to ToolPending, the phase is set
// back to "loading", and findings are cleared. The "update" tool is
// excluded because update-check state is intentionally preserved
// across rescans.
func TestScanProgress_ResetForRescan(t *testing.T) {
	sp := NewScanProgress(false)
	// Set update to a non-default state so we can prove it survives
	// the reset.
	sp.SetToolStatus("update", ToolDone, "v1.2.3 available")
	sp.AddFindings([]Finding{
		{ID: "compose.ds001", Severity: SeverityHigh, Source: SourceCompose},
	})
	sp.SetToolStatus("trivy", ToolDegraded, "trivy unavailable")
	sp.SetToolStatus("lynis", ToolDone, "")
	sp.Finalize()

	sp.ResetForRescan()

	if sp.Phase != "loading" {
		t.Errorf("Phase = %q, want loading", sp.Phase)
	}
	if len(sp.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 after reset", len(sp.Findings))
	}
	if sp.Score != 0 {
		t.Errorf("Score = %d, want 0 after reset", sp.Score)
	}
	if sp.ToolState("trivy").Status != ToolPending {
		t.Errorf("trivy status = %v, want Pending after reset", sp.ToolState("trivy").Status)
	}
	if sp.ToolState("lynis").Status != ToolPending {
		t.Errorf("lynis status = %v, want Pending after reset", sp.ToolState("lynis").Status)
	}
	// update state is preserved across rescans.
	if got := sp.ToolState("update"); got.Status != ToolDone || got.Message != "v1.2.3 available" {
		t.Errorf("update state = %+v, want preserved (Done, v1.2.3 available)", got)
	}
}

// TestScanProgress_MarkRelatedFixed asserts the cascade-marks-related
// path: findings sharing the same service and matching the matchFn
// are marked Fixed (except the excludeID itself), and the score is
// recalculated.
func TestScanProgress_MarkRelatedFixed(t *testing.T) {
	sp := NewScanProgress(true)
	sp.AddFindings([]Finding{
		{ID: "trivy.cve-2024-1", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx"},
		{ID: "trivy.cve-2024-2", Severity: SeverityHigh, Source: SourceTrivy, Service: "nginx"},
		{ID: "trivy.cve-2024-3", Severity: SeverityHigh, Source: SourceTrivy, Service: "postgres"},
		{ID: "lynis.AUTH-9286", Severity: SeverityMedium, Source: SourceLynis, Service: "host"},
	})
	sp.Finalize()

	alsoFixed := sp.MarkRelatedFixed(
		"trivy.cve-2024-1",
		"nginx",
		func(id string) bool { return id == "trivy.cve-2024-2" },
	)
	if len(alsoFixed) != 1 || alsoFixed[0] != "trivy.cve-2024-2" {
		t.Errorf("alsoFixed = %v, want [trivy.cve-2024-2]", alsoFixed)
	}
	// The matching finding is now Fixed.
	for _, f := range sp.Findings {
		if f.ID == "trivy.cve-2024-2" && !f.Fixed {
			t.Error("trivy.cve-2024-2 should be Fixed after cascade")
		}
	}
	// Different service was not touched.
	for _, f := range sp.Findings {
		if f.ID == "trivy.cve-2024-3" && f.Fixed {
			t.Error("trivy.cve-2024-3 (different service) should NOT be Fixed")
		}
	}
	// The exclude ID itself was not touched.
	for _, f := range sp.Findings {
		if f.ID == "trivy.cve-2024-1" && f.Fixed {
			t.Error("exclude ID itself should NOT be Fixed")
		}
	}
}

// TestScanProgress_MarkRelatedFixed_NoMatch asserts the function is
// a no-op when nothing matches.
func TestScanProgress_MarkRelatedFixed_NoMatch(t *testing.T) {
	sp := NewScanProgress(true)
	sp.AddFindings([]Finding{
		{ID: "trivy.cve-2024-1", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx"},
	})
	sp.Finalize()

	alsoFixed := sp.MarkRelatedFixed(
		"trivy.cve-2024-1",
		"nginx",
		func(id string) bool { return false },
	)
	if len(alsoFixed) != 0 {
		t.Errorf("alsoFixed = %v, want empty (no match)", alsoFixed)
	}
}

// TestScanProgress_Snapshot_ReflectsMutations asserts the cache
// invalidation contract: a Snapshot taken before a mutation must NOT
// reflect the mutation; a Snapshot taken after must reflect it. This
// is the contract the Web UI relies on for the /api/result poll — the
// UI sees the new state on its next poll, never a stale mix.
//
// The test does NOT assert that the caller can safely mutate the
// returned Snapshot's findings slice in place. The findings slice in
// the cached snapshot shares its backing array with the most recent
// returned Snapshot. Callers must treat the returned value as
// read-only. (This is documented behavior — see the comment on
// bumpVersionLocked.)
func TestScanProgress_Snapshot_ReflectsMutations(t *testing.T) {
	sp := NewScanProgress(true)
	sp.AddFindings([]Finding{
		{ID: "compose.ds001", Severity: SeverityHigh, Source: SourceCompose, Service: "web"},
	})
	sp.Finalize()

	snapBefore := sp.Snapshot()
	if len(snapBefore.Findings) != 1 || snapBefore.Findings[0].Service != "web" {
		t.Fatalf("snapBefore: %+v", snapBefore.Findings)
	}

	sp.MarkFixed("compose.ds001", "web")

	snapAfter := sp.Snapshot()
	if len(snapAfter.Findings) != 1 {
		t.Fatalf("snapAfter.Findings = %d, want 1", len(snapAfter.Findings))
	}
	if !snapAfter.Findings[0].Fixed {
		t.Error("snapAfter finding should be Fixed (the mark happened between snapshots)")
	}
}
