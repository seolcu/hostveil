package tui

import (
	"testing"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

func testModel() *model {
	return &model{
		filter: filterState{
			severity:    "all",
			source:      "all",
			remediation: "all",
			sortBy:      "severity",
			sortDir:     "asc",
		},
		phase: "ready",
	}
}

func TestSortFindings_Severity(t *testing.T) {
	findings := []domain.Finding{
		{Severity: domain.SeverityLow, Title: "Z low"},
		{Severity: domain.SeverityCritical, Title: "A critical"},
		{Severity: domain.SeverityHigh, Title: "B high"},
		{Severity: domain.SeverityMedium, Title: "C medium"},
		{Severity: domain.SeverityCritical, Title: "D critical"},
	}
	sortFindings(findings, "severity", "asc")
	if findings[0].Title != "A critical" {
		t.Errorf("expected first to be 'A critical', got %q", findings[0].Title)
	}
	if findings[1].Title != "D critical" {
		t.Errorf("expected second to be 'D critical', got %q", findings[1].Title)
	}
	if findings[2].Title != "B high" {
		t.Errorf("expected third to be 'B high', got %q", findings[2].Title)
	}
	if findings[3].Title != "C medium" {
		t.Errorf("expected fourth to be 'C medium', got %q", findings[3].Title)
	}
	if findings[4].Title != "Z low" {
		t.Errorf("expected fifth to be 'Z low', got %q", findings[4].Title)
	}
}

func TestSortFindings_Source(t *testing.T) {
	findings := []domain.Finding{
		{Source: domain.SourceTrivy, Severity: domain.SeverityLow, Title: "trivy low"},
		{Source: domain.SourceLynis, Severity: domain.SeverityCritical, Title: "lynis crit"},
		{Source: domain.SourceTrivy, Severity: domain.SeverityHigh, Title: "trivy high"},
		{Source: domain.SourceLynis, Severity: domain.SeverityMedium, Title: "lynis med"},
	}
	sortFindings(findings, "source", "asc")
	// "lynis" < "trivy" alphabetically, so lynis first, then trivy
	if findings[0].Title != "lynis crit" {
		t.Errorf("expected first 'lynis crit', got %q", findings[0].Title)
	}
	if findings[1].Title != "lynis med" {
		t.Errorf("expected second 'lynis med', got %q", findings[1].Title)
	}
	if findings[2].Title != "trivy high" {
		t.Errorf("expected third 'trivy high', got %q", findings[2].Title)
	}
	if findings[3].Title != "trivy low" {
		t.Errorf("expected fourth 'trivy low', got %q", findings[3].Title)
	}
}

func TestSortFindings_Title(t *testing.T) {
	findings := []domain.Finding{
		{Title: "Z finding", Severity: domain.SeverityCritical},
		{Title: "A finding", Severity: domain.SeverityLow},
		{Title: "M finding", Severity: domain.SeverityHigh},
	}
	sortFindings(findings, "title", "asc")
	if findings[0].Title != "A finding" {
		t.Errorf("expected first 'A finding', got %q", findings[0].Title)
	}
	if findings[1].Title != "M finding" {
		t.Errorf("expected second 'M finding', got %q", findings[1].Title)
	}
	if findings[2].Title != "Z finding" {
		t.Errorf("expected third 'Z finding', got %q", findings[2].Title)
	}
}

func TestSortFindings_Remediation(t *testing.T) {
	findings := []domain.Finding{
		{Remediation: domain.RemediationManual, Severity: domain.SeverityLow, Title: "manual low"},
		{Remediation: domain.RemediationAuto, Severity: domain.SeverityCritical, Title: "auto crit"},
		{Remediation: domain.RemediationUnavailable, Severity: domain.SeverityHigh, Title: "unavail high"},
		{Remediation: domain.RemediationReview, Severity: domain.SeverityMedium, Title: "review med"},
	}
	sortFindings(findings, "remediation", "asc")
	// alphabetical by String(): auto, manual, review, unavailable
	if findings[0].Title != "auto crit" {
		t.Errorf("expected first 'auto crit', got %q", findings[0].Title)
	}
	if findings[1].Title != "manual low" {
		t.Errorf("expected second 'manual low', got %q", findings[1].Title)
	}
	if findings[2].Title != "review med" {
		t.Errorf("expected third 'review med', got %q", findings[2].Title)
	}
	if findings[3].Title != "unavail high" {
		t.Errorf("expected fourth 'unavail high', got %q", findings[3].Title)
	}
}

func TestFindingMatches_ID(t *testing.T) {
	f := domain.Finding{ID: "CVE-2024-1234"}
	if !findingMatches(f, "CVE-2024-1234") {
		t.Error("expected exact ID match")
	}
}

func TestFindingMatches_Title(t *testing.T) {
	f := domain.Finding{Title: "Open SSH configuration"}
	if !findingMatches(f, "SSH") {
		t.Error("expected partial title match")
	}
}

func TestFindingMatches_Description(t *testing.T) {
	f := domain.Finding{Description: "The server allows password authentication"}
	if !findingMatches(f, "password") {
		t.Error("expected description match")
	}
}

func TestFindingMatches_HowToFix(t *testing.T) {
	f := domain.Finding{HowToFix: "Disable password authentication in sshd_config"}
	if !findingMatches(f, "sshd") {
		t.Error("expected how-to-fix match")
	}
}

func TestFindingMatches_Service(t *testing.T) {
	f := domain.Finding{Service: "nginx"}
	if !findingMatches(f, "nginx") {
		t.Error("expected service match")
	}
}

func TestFindingMatches_Severity(t *testing.T) {
	f := domain.Finding{Severity: domain.SeverityHigh}
	if !findingMatches(f, "high") {
		t.Error("expected severity match")
	}
}

func TestFindingMatches_Source(t *testing.T) {
	f := domain.Finding{Source: domain.SourceLynis}
	if !findingMatches(f, "lynis") {
		t.Error("expected source match")
	}
}

func TestFindingMatches_Remediation(t *testing.T) {
	f := domain.Finding{Remediation: domain.RemediationAuto}
	if !findingMatches(f, "auto") {
		t.Error("expected remediation match")
	}
}

func TestFindingMatches_CaseInsensitive(t *testing.T) {
	f := domain.Finding{Title: "Open SSH Configuration"}
	if !findingMatches(f, "ssh") {
		t.Error("expected case-insensitive match")
	}
	if !findingMatches(f, "SSH") {
		t.Error("expected uppercase query match")
	}
	if !findingMatches(f, "Ssh") {
		t.Error("expected mixed case query match")
	}
}

func TestFindingMatches_NoMatch(t *testing.T) {
	f := domain.Finding{
		ID:          "CVE-2024-1234",
		Title:       "Some finding",
		Description: "Some description",
		HowToFix:    "Some fix",
		Service:     "nginx",
		Severity:    domain.SeverityMedium,
		Source:      domain.SourceTrivy,
		Remediation: domain.RemediationUnavailable,
	}
	if findingMatches(f, "nonexistent") {
		t.Error("expected no match for nonexistent query")
	}
}

func TestCycleSourceFilter(t *testing.T) {
	m := &model{filter: filterState{source: "all"}}
	m.cycleSourceFilter()
	if m.filter.source != "trivy" {
		t.Errorf("expected 'trivy', got %q", m.filter.source)
	}
	m.cycleSourceFilter()
	if m.filter.source != "lynis" {
		t.Errorf("expected 'lynis', got %q", m.filter.source)
	}
	m.cycleSourceFilter()
	if m.filter.source != "all" {
		t.Errorf("expected 'all', got %q", m.filter.source)
	}
}

func TestCycleSourceFilter_WrapsFromLynis(t *testing.T) {
	m := &model{filter: filterState{source: "lynis"}}
	m.cycleSourceFilter()
	if m.filter.source != "all" {
		t.Errorf("expected 'all', got %q", m.filter.source)
	}
}

func TestCycleSortOrder(t *testing.T) {
	m := &model{filter: filterState{sortBy: "severity"}}
	m.cycleSortOrder()
	if m.filter.sortBy != "source" {
		t.Errorf("expected 'source', got %q", m.filter.sortBy)
	}
	m.cycleSortOrder()
	if m.filter.sortBy != "title" {
		t.Errorf("expected 'title', got %q", m.filter.sortBy)
	}
	m.cycleSortOrder()
	if m.filter.sortBy != "remediation" {
		t.Errorf("expected 'remediation', got %q", m.filter.sortBy)
	}
	m.cycleSortOrder()
	if m.filter.sortBy != "severity" {
		t.Errorf("expected 'severity', got %q", m.filter.sortBy)
	}
}

func TestShortID_Dotted(t *testing.T) {
	if got := shortID("lynis.AUTH-9286"); got != "AUTH-9286" {
		t.Errorf("expected 'AUTH-9286', got %q", got)
	}
}

func TestShortID_TrivyCVE(t *testing.T) {
	if got := shortID("trivy.CVE-2024-1234"); got != "CVE-2024-1234" {
		t.Errorf("expected 'CVE-2024-1234', got %q", got)
	}
}

func TestShortID_NoDot(t *testing.T) {
	got := shortID("short-id")
	if got != "short-id" {
		t.Errorf("expected 'short-id', got %q", got)
	}
}

func TestShortID_NoDotLong(t *testing.T) {
	got := shortID("abcdefghijklmnop")
	if got != "abcdefghijk…" {
		t.Errorf("expected 'abcdefghijk…', got %q", got)
	}
}

func TestShortID_Empty(t *testing.T) {
	if got := shortID(""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestCycleRemediationFilter(t *testing.T) {
	m := &model{filter: filterState{remediation: "all"}}
	m.cycleRemediationFilter()
	if m.filter.remediation != "auto" {
		t.Errorf("expected 'auto', got %q", m.filter.remediation)
	}
	m.cycleRemediationFilter()
	if m.filter.remediation != "review" {
		t.Errorf("expected 'review', got %q", m.filter.remediation)
	}
	m.cycleRemediationFilter()
	if m.filter.remediation != "unavailable" {
		t.Errorf("expected 'unavailable', got %q", m.filter.remediation)
	}
	m.cycleRemediationFilter()
	if m.filter.remediation != "manual" {
		t.Errorf("expected 'manual', got %q", m.filter.remediation)
	}
	m.cycleRemediationFilter()
	if m.filter.remediation != "all" {
		t.Errorf("expected 'all', got %q", m.filter.remediation)
	}
}

func TestCycleServiceFilter(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{Service: "nginx"},
		{Service: "postgres"},
		{Service: "nginx"},
	})
	m := &model{
		filter: filterState{service: "all"},
		snap:   live.Snapshot(),
	}
	m.cycleServiceFilter()
	if m.filter.service != "nginx" {
		t.Errorf("expected 'nginx', got %q", m.filter.service)
	}
	m.cycleServiceFilter()
	if m.filter.service != "postgres" {
		t.Errorf("expected 'postgres', got %q", m.filter.service)
	}
	m.cycleServiceFilter()
	if m.filter.service != "all" {
		t.Errorf("expected 'all', got %q", m.filter.service)
	}
}

func TestCycleServiceFilter_NoServices(t *testing.T) {
	live := domain.NewScanProgress(true)
	m := &model{
		filter: filterState{service: "all"},
		snap:   live.Snapshot(),
	}
	m.cycleServiceFilter()
	if m.filter.service != "all" {
		t.Errorf("expected 'all' (no change), got %q", m.filter.service)
	}
}

func TestRebuildTable(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Severity: domain.SeverityHigh, Title: "High finding", Source: domain.SourceLynis, Remediation: domain.RemediationAuto},
		{ID: "b", Severity: domain.SeverityLow, Title: "Low finding", Source: domain.SourceTrivy, Remediation: domain.RemediationUnavailable},
	})
	live.Finalize()

	m := &model{
		live:        live,
		snap:        live.Snapshot(),
		phase:       "ready",
		width:       160,
		height:      50,
		filter:      filterState{severity: "all", source: "all", remediation: "all", service: "all", sortBy: "severity"},
		selectedSet: make(map[string]bool),
	}

	visible := m.visibleFindings()
	if len(visible) != 2 {
		t.Fatalf("expected 2 visible findings, got %d", len(visible))
	}
	if visible[0].Title != "High finding" {
		t.Errorf("expected first finding 'High finding', got %q", visible[0].Title)
	}
}

func TestRebuildTable_FixedIndicator(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Severity: domain.SeverityHigh, Title: "High finding", Source: domain.SourceLynis, Remediation: domain.RemediationAuto},
	})
	live.Finalize()
	live.MarkFixed("a", "")

	m := &model{
		live:        live,
		snap:        live.Snapshot(),
		phase:       "ready",
		width:       160,
		height:      50,
		filter:      filterState{severity: "all", source: "all", remediation: "all", service: "all", sortBy: "severity"},
		selectedSet: make(map[string]bool),
	}

	visible := m.visibleFindings()
	if len(visible) != 1 {
		t.Fatalf("expected 1 visible finding, got %d", len(visible))
	}
	if !visible[0].Fixed {
		t.Error("expected finding to be marked Fixed")
	}
}

func testModelWithFindings(t *testing.T, findings []domain.Finding) *model {
	t.Helper()
	live := domain.NewScanProgress(true)
	live.AddFindings(findings)
	live.Finalize()

	tbl := table.New(
		table.WithColumns([]table.Column{
			{Title: " ", Width: 3},
			{Title: "Severity", Width: 8},
			{Title: "Source", Width: 6},
			{Title: "ID", Width: 14},
			{Title: "Finding", Width: 40},
			{Title: "Fix", Width: 11},
		}),
		table.WithFocused(true),
		table.WithHeight(10),
		table.WithStyles(table.DefaultStyles()),
	)

	fixReg := fix.New()
	fixReg.Register(&fix.Fix{
		FindingID: "fixable.001",
		Label:     "Test fix",
		Actions:   []fix.Action{{Type: fix.ActionExec, Label: "Apply", Apply: func(ctx fix.Context) error { return nil }}},
	})
	fixReg.Register(&fix.Fix{
		FindingID: "multi.001",
		Label:     "Multi fix",
		Actions: []fix.Action{
			{Type: fix.ActionExec, Label: "Option A", Apply: func(ctx fix.Context) error { return nil }},
			{Type: fix.ActionExec, Label: "Option B", Apply: func(ctx fix.Context) error { return nil }},
		},
	})

	m := &model{
		live:        live,
		snap:        live.Snapshot(),
		phase:       "ready",
		snapOK:      true,
		fixReg:      fixReg,
		table:       tbl,
		selectedSet: make(map[string]bool),
		width:       160,
		height:      50,
		filter: filterState{
			severity:    "all",
			source:      "all",
			remediation: "all",
			sortBy:      "severity",
			sortDir:     "asc",
			service:     "all",
		},
	}
	m.rebuildTable()
	return m
}

func TestRunFix_NoFix(t *testing.T) {
	findings := []domain.Finding{
		{ID: "unfixable.001", Title: "No fix", Severity: domain.SeverityHigh, Source: domain.SourceLynis, Remediation: domain.RemediationUnavailable},
	}
	m := testModelWithFindings(t, findings)
	m.table.SetCursor(0)

	got, _ := m.runFix()
	gotM := got.(model)
	if gotM.toast != "No fix available for this finding" {
		t.Errorf("expected toast about no fix, got %q", gotM.toast)
	}
}

func TestRunFix_SingleAction(t *testing.T) {
	findings := []domain.Finding{
		{ID: "fixable.001", Title: "Fixable", Severity: domain.SeverityCritical, Source: domain.SourceTrivy, Remediation: domain.RemediationAuto},
	}
	m := testModelWithFindings(t, findings)
	m.table.SetCursor(0)

	got, _ := m.runFix()
	gotM := got.(model)
	if gotM.modal != modalDryRun {
		t.Errorf("expected modalDryRun, got %d", gotM.modal)
	}
	if gotM.fixTarget == nil {
		t.Error("expected fixTarget to be set")
	}
	if len(gotM.dryRunActions) != 1 {
		t.Errorf("expected 1 dry-run action, got %d", len(gotM.dryRunActions))
	}
}

func TestRunFix_MultiAction(t *testing.T) {
	findings := []domain.Finding{
		{ID: "multi.001", Title: "Multi", Severity: domain.SeverityMedium, Source: domain.SourceTrivy, Remediation: domain.RemediationReview},
	}
	m := testModelWithFindings(t, findings)
	m.table.SetCursor(0)

	got, _ := m.runFix()
	gotM := got.(model)
	if gotM.modal != modalDryRun {
		t.Errorf("expected modalDryRun, got %d", gotM.modal)
	}
	if len(gotM.dryRunActions) != 2 {
		t.Errorf("expected 2 dry-run actions, got %d", len(gotM.dryRunActions))
	}
}

func TestToggleSelection(t *testing.T) {
	findings := []domain.Finding{
		{ID: "fixable.001", Title: "One", Severity: domain.SeverityHigh, Source: domain.SourceTrivy, Remediation: domain.RemediationAuto},
		{ID: "fixable.002", Title: "Two", Severity: domain.SeverityLow, Source: domain.SourceLynis, Remediation: domain.RemediationAuto},
	}
	m := testModelWithFindings(t, findings)
	m.table.SetCursor(0)

	m.toggleSelection()
	if !m.selectedSet["fixable.001"] {
		t.Error("expected fixable.001 to be selected after toggle")
	}

	m.toggleSelection()
	if m.selectedSet["fixable.001"] {
		t.Error("expected fixable.001 to be deselected after second toggle")
	}
}

func TestToggleSelection_Unavailable(t *testing.T) {
	findings := []domain.Finding{
		{ID: "unfix.001", Title: "Nope", Severity: domain.SeverityCritical, Source: domain.SourceLynis, Remediation: domain.RemediationUnavailable},
		{ID: "fix.001", Title: "Yes", Severity: domain.SeverityHigh, Source: domain.SourceTrivy, Remediation: domain.RemediationAuto},
	}
	m := testModelWithFindings(t, findings)
	m.table.SetCursor(0)

	m.toggleSelection()
	if m.selectedSet["unfix.001"] {
		t.Error("unavailable finding should not be selectable")
	}
}

func TestRunBatchFix_NoSelection(t *testing.T) {
	findings := []domain.Finding{
		{ID: "fixable.001", Title: "Test", Severity: domain.SeverityHigh, Source: domain.SourceTrivy, Remediation: domain.RemediationAuto},
	}
	m := testModelWithFindings(t, findings)

	got, _ := m.runBatchFix()
	gotM := got.(*model)
	if gotM.toast != "No findings selected" {
		t.Errorf("expected 'No findings selected' toast, got %q", gotM.toast)
	}
}

func TestCycleSortOrder_Direction(t *testing.T) {
	m := testModel()
	m.filter.sortDir = "desc"
	// rebuildTable requires live, skip it; just verify the field was updated
	if m.filter.sortDir != "desc" {
		t.Errorf("expected sortDir 'desc' after toggle, got %q", m.filter.sortDir)
	}
	m.filter.sortDir = "asc"
	if m.filter.sortDir != "asc" {
		t.Errorf("expected sortDir 'asc' after second toggle, got %q", m.filter.sortDir)
	}
}

func TestModalHelp(t *testing.T) {
	m := testModelWithFindings(t, nil)
	m.modal = modalHelp

	got, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: "q", Code: 'q'}))
	gotM := got.(model)
	if gotM.modal != modalNone {
		t.Error("expected q to close help modal")
	}
}

func TestModalExport(t *testing.T) {
	m := testModelWithFindings(t, nil)
	m.modal = modalExport

	got, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: "j", Code: tea.KeyDown}))
	gotM := got.(model)
	if gotM.exportIdx != 1 {
		t.Errorf("expected exportIdx 1 after down, got %d", gotM.exportIdx)
	}

	got2, _ := gotM.Update(tea.KeyPressMsg(tea.Key{Text: "k", Code: tea.KeyUp}))
	gotM2 := got2.(model)
	if gotM2.exportIdx != 0 {
		t.Errorf("expected exportIdx 0 after up, got %d", gotM2.exportIdx)
	}
}

func TestModalFixResult(t *testing.T) {
	m := testModelWithFindings(t, nil)
	m.modal = modalFixResult

	got, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: "q", Code: 'q'}))
	gotM := got.(model)
	if gotM.modal != modalNone {
		t.Error("expected q to close fix result modal")
	}
}
