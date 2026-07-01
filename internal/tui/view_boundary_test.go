package tui

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

// TestView_LoadingAtBoundarySizes renders the loading screen at terminal
// sizes from 40x10 (minimum supported) to 240x80 (very wide) and asserts
// no panic and that the output contains the expected brand line.
func TestView_LoadingAtBoundarySizes(t *testing.T) {
	sizes := []struct{ w, h int }{
		{40, 10}, {40, 24}, {60, 20}, {80, 24}, {120, 40}, {160, 50}, {240, 80},
	}
	for _, s := range sizes {
		m := &model{
			live: domain.NewScanProgress(false),
			filter: filterState{
				severity: "all", source: "all", remediation: "all",
				sortBy: "severity", sortDir: "asc",
			},
			phase: "loading",
		}
		m.width = s.w
		m.height = s.h
		// Must not panic.
		view := m.View()
		if !strings.Contains(view.Content, "hostveil") {
			t.Errorf("size %dx%d: loading view missing brand", s.w, s.h)
		}
	}
}

// TestView_ReadyEmptySnapshot renders the main screen with a snapshot
// that has zero findings (the "Clean" state) and zero tool updates.
// Asserts no panic, "Clean" label present, and content is not empty.
func TestView_ReadyEmptySnapshot(t *testing.T) {
	live := domain.NewScanProgress(false)
	live.Finalize() // empty scan, phase=complete
	m := &model{
		live: live,
		filter: filterState{
			severity: "all", source: "all", remediation: "all",
			sortBy: "severity", sortDir: "asc",
		},
		phase: "ready",
	}
	m.width = 120
	m.height = 40
	view := m.View()
	if !strings.Contains(view.Content, "Clean") {
		t.Errorf("empty snapshot should render Clean, got: %q", view.Content)
	}
}

// TestView_ReadyWithFindings renders the main screen with 14 findings
// (matching the mock fixture) at three widths. Asserts no panic and that
// the table is present.
func TestView_ReadyWithFindings(t *testing.T) {
	findings := makeTestFindings(14)
	for _, w := range []int{80, 120, 200, 280} {
		m := testModelWithFindings(t, findings)
		m.width = w
		m.height = 40
		view := m.View()
		// Should contain the brand "hostveil" and the table headers.
		if !strings.Contains(view.Content, "FINDINGS") {
			t.Errorf("width %d: missing FINDINGS header", w)
		}
	}
}

// TestView_AllFixed renders the main screen with 14 fixed findings.
// All should be marked Fixed in the table.
func TestView_AllFixed(t *testing.T) {
	findings := makeTestFindings(14)
	for i := range findings {
		findings[i].Fixed = true
	}
	m := testModelWithFindings(t, findings)
	m.width = 120
	m.height = 40
	view := m.View()
	if !strings.Contains(view.Content, "Fixed") {
		t.Errorf("all-fixed snapshot should show Fixed label, got: %q", view.Content)
	}
}

// TestView_LoadingTooSmall renders the loading screen at a size below the
// 40x10 threshold. Should fall back to the "Terminal too small" message.
func TestView_LoadingTooSmall(t *testing.T) {
	m := &model{
		live: domain.NewScanProgress(false),
		filter: filterState{
			severity: "all", source: "all", remediation: "all",
			sortBy: "severity", sortDir: "asc",
		},
		phase: "loading",
	}
	m.width = 20
	m.height = 8
	view := m.View()
	if !strings.Contains(view.Content, "Terminal too small") {
		t.Errorf("too-small view should show fallback message")
	}
}

// TestView_MainTooSmall renders the main screen at a too-small size.
// Should fall back to the "Terminal too small" message.
func TestView_MainTooSmall(t *testing.T) {
	findings := makeTestFindings(3)
	m := testModelWithFindings(t, findings)
	m.width = 20
	m.height = 8
	view := m.View()
	if !strings.Contains(view.Content, "Terminal too small") {
		t.Errorf("too-small main view should show fallback message")
	}
}

// TestView_ModalOverlaysReady verifies that each modal renders on top of
// the main view without crashing. The compositor centers the modal.
func TestView_ModalOverlaysReady(t *testing.T) {
	findings := makeTestFindings(3)
	for _, mm := range []modalMode{modalHelp, modalFilter, modalExport, modalFixResult} {
		m := testModelWithFindings(t, findings)
		m.width = 120
		m.height = 40
		m.modal = mm
		view := m.View()
		if len(view.Content) == 0 {
			t.Errorf("modal %d: empty view", mm)
		}
	}
}

// TestView_WithToast renders the main view with a toast. The toast should
// be visible in the footer area of the list pane.
func TestView_WithToast(t *testing.T) {
	findings := makeTestFindings(3)
	m := testModelWithFindings(t, findings)
	m.width = 120
	m.height = 40
	m.toast = "Filters cleared"
	view := m.View()
	if !strings.Contains(view.Content, "Filters cleared") {
		t.Errorf("toast not visible in view: %q", view.Content)
	}
}

// TestView_WithSelectedSet renders the main view with selected items.
// The footer should show "N selected — press f to batch fix".
func TestView_WithSelectedSet(t *testing.T) {
	findings := makeTestFindings(3)
	m := testModelWithFindings(t, findings)
	m.width = 120
	m.height = 40
	m.selectedSet = map[string]bool{findings[0].ID: true, findings[1].ID: true}
	view := m.View()
	if !strings.Contains(view.Content, "selected") {
		t.Errorf("selection count not in view: %q", view.Content)
	}
}

// TestView_LoadingWithAllToolsDone renders the loading screen with all
// tools marked done. Progress should be 100%.
func TestView_LoadingWithAllToolsDone(t *testing.T) {
	live := domain.NewScanProgress(false)
	m := &model{
		live: live,
		filter: filterState{
			severity: "all", source: "all", remediation: "all",
			sortBy: "severity", sortDir: "asc",
		},
		phase: "loading",
	}
	if m.snap.Tools == nil {
		m.snap.Tools = map[string]domain.ToolStateJSON{}
	}
	m.snap.Tools["update"] = domain.ToolStateJSON{Status: int(domain.ToolDone), Message: "v1.2.3 available"}
	m.snap.Tools["trivy"] = domain.ToolStateJSON{Status: int(domain.ToolDone), Message: ""}
	m.snap.Tools["lynis"] = domain.ToolStateJSON{Status: int(domain.ToolDone), Message: ""}
	m.snap.Tools["compose"] = domain.ToolStateJSON{Status: int(domain.ToolDone), Message: ""}
	m.width = 120
	m.height = 40
	view := m.View()
	if !strings.Contains(view.Content, "100%") {
		t.Errorf("all-done progress should be 100%%, got: %q", view.Content)
	}
}

// TestView_DetailPaneAtBoundaryWidths renders the detail pane at
// various widths to catch overflow/clipping issues.
func TestView_DetailPaneAtBoundaryWidths(t *testing.T) {
	findings := makeTestFindings(3)
	// Use a long-title finding to stress-wrap.
	findings[0].Title = "This is a very long finding title that should wrap cleanly across multiple lines without overflowing the detail panel width or breaking layout"
	for _, w := range []int{60, 80, 120, 200} {
		m := testModelWithFindings(t, findings)
		m.width = w
		m.height = 40
		m.mode = paneDetail
		view := m.View()
		// Must not panic and content should not be empty.
		if len(view.Content) == 0 {
			t.Errorf("width %d detail view empty", w)
		}
	}
}

// TestView_NarrowSplitDetail is the width regime where splitDetail
// returns false (m.width < 116). Detail should take full width.
func TestView_NarrowSplitDetail(t *testing.T) {
	findings := makeTestFindings(3)
	m := testModelWithFindings(t, findings)
	m.width = 100
	m.height = 30
	m.mode = paneDetail
	view := m.View()
	if len(view.Content) == 0 {
		t.Errorf("narrow detail view empty")
	}
}

// TestView_WideSplitDetail is the width regime where splitDetail
// returns true (m.width >= 116). List and detail should be side by side.
func TestView_WideSplitDetail(t *testing.T) {
	findings := makeTestFindings(3)
	m := testModelWithFindings(t, findings)
	m.width = 200
	m.height = 30
	view := m.View()
	if !strings.Contains(view.Content, "FINDINGS") {
		t.Errorf("wide split view should include list pane")
	}
}

// TestView_FilterPanelWide renders the filter panel, which appears
// when m.width >= 190.
func TestView_FilterPanelWide(t *testing.T) {
	findings := makeTestFindings(3)
	m := testModelWithFindings(t, findings)
	m.width = 200
	m.height = 40
	view := m.View()
	if !strings.Contains(view.Content, "SEARCH FINDINGS") {
		t.Errorf("wide view should show filter panel")
	}
}

// TestView_LoadingShort renders the loading screen at a very short
// height (< 10) to exercise the "Terminal too small" branch.
func TestView_LoadingShort(t *testing.T) {
	m := &model{
		live: domain.NewScanProgress(false),
		filter: filterState{
			severity: "all", source: "all", remediation: "all",
			sortBy: "severity", sortDir: "asc",
		},
		phase: "loading",
	}
	m.width = 80
	m.height = 5
	view := m.View()
	if !strings.Contains(view.Content, "Terminal too small") {
		t.Errorf("short height should show fallback")
	}
}

// TestView_LoadingTall renders at a very tall height. Should not crash
// and should still show the loading panel.
func TestView_LoadingTall(t *testing.T) {
	m := &model{
		live: domain.NewScanProgress(false),
		filter: filterState{
			severity: "all", source: "all", remediation: "all",
			sortBy: "severity", sortDir: "asc",
		},
		phase: "loading",
	}
	m.width = 120
	m.height = 200
	view := m.View()
	if !strings.Contains(view.Content, "hostveil") {
		t.Errorf("tall view missing brand")
	}
}

// TestView_ModalFixProgressNoInput ensures the batch-fix progress modal
// is present and renders without crashing. The modal blocks input by
// design (returns m, nil for any key), but View should still work.
func TestView_ModalFixProgressNoInput(t *testing.T) {
	m := &model{
		live: domain.NewScanProgress(false),
		filter: filterState{
			severity: "all", source: "all", remediation: "all",
			sortBy: "severity", sortDir: "asc",
		},
		phase: "ready",
	}
	m.modal = modalFixProgress
	m.fixProgress = 3
	m.fixProgressTotal = 10
	m.width = 120
	m.height = 40
	view := m.View()
	if !strings.Contains(view.Content, "Applying fixes") {
		t.Errorf("progress modal missing title")
	}
}

// TestView_NoHostnameNoIP renders with an empty Hostname and LocalIP.
// The sysInfoLine should be empty and not break layout.
func TestView_NoHostnameNoIP(t *testing.T) {
	findings := makeTestFindings(3)
	m := testModelWithFindings(t, findings)
	m.width = 120
	m.height = 40
	m.snap.Hostname = ""
	m.snap.LocalIP = ""
	view := m.View()
	if len(view.Content) == 0 {
		t.Errorf("view with no hostname/ip should still render")
	}
}

// makeTestFindings creates a slice of n findings spanning all severity
// levels and sources, similar to the mock fixture used in e2e tests.
func makeTestFindings(n int) []domain.Finding {
	severities := []domain.Severity{
		domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow,
	}
	sources := []domain.Source{domain.SourceTrivy, domain.SourceLynis, domain.SourceCompose}
	remKinds := []domain.RemediationKind{
		domain.RemediationAuto, domain.RemediationReview,
		domain.RemediationUnavailable, domain.RemediationManual,
	}
	services := []string{"nginx:1.24", "postgres", "host", ""}
	ids := []string{
		"trivy.cve-2024-0001", "compose.ds001", "lynis.AUTH-9286",
		"compose.dr004", "trivy.ds001", "lynis.FILE-6310",
	}
	out := make([]domain.Finding, n)
	for i := range out {
		out[i] = domain.Finding{
			ID:          ids[i%len(ids)],
			Title:       "Test finding " + string(rune('A'+i%26)),
			Description: "Description for finding " + string(rune('A'+i%26)),
			HowToFix:    "Fix " + string(rune('A'+i%26)),
			Severity:    severities[i%len(severities)],
			Source:      sources[i%len(sources)],
			Service:     services[i%len(services)],
			Remediation: remKinds[i%len(remKinds)],
			Evidence:    map[string]string{"key": "value"},
		}
	}
	return out
}
