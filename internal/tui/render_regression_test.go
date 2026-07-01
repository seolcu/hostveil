package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

func readyModelForRenderRegression(t *testing.T, findings []domain.Finding, width, height int) *model {
	t.Helper()

	live := domain.NewScanProgress(true)
	live.AddFindings(findings)
	live.Finalize()

	m := NewApp(live, fix.New())
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.width = width
	m.height = height
	m.rebuildTable()
	return m
}

func assertRenderedWidthAtMost(t *testing.T, output string, width int) {
	t.Helper()
	for i, line := range strings.Split(output, "\n") {
		if got := lipgloss.Width(line); got > width {
			t.Fatalf("line %d exceeds terminal width: got %d, want <= %d: %q", i+1, got, width, line)
		}
	}
}

func TestView_BoundaryDimensionsPreserveVisibleStateAndWidth(t *testing.T) {
	cases := []struct {
		name     string
		width    int
		height   int
		findings []domain.Finding
		prepare  func(*model)
		want     []string
	}{
		{
			name:   "minimum clean snapshot",
			width:  40,
			height: 10,
			want:   []string{"Clean", "0 visible"},
		},
		{
			name:   "default active selection",
			width:  120,
			height: 32,
			findings: []domain.Finding{
				{ID: "selectable.001", Title: "Selectable SSH finding", Severity: domain.SeverityHigh, Source: domain.SourceLynis, Remediation: domain.RemediationAuto},
				{ID: "manual.001", Title: "Manual-only finding", Severity: domain.SeverityMedium, Source: domain.SourceTrivy, Remediation: domain.RemediationManual},
			},
			prepare: func(m *model) {
				m.selectedSet["selectable.001"] = true
				m.rebuildTable()
			},
			want: []string{"◆", "1 selected — press f to batch fix", "Selectable SSH finding"},
		},
		{
			name:   "wide all fixed snapshot",
			width:  220,
			height: 48,
			findings: []domain.Finding{
				{ID: "fixed.001", Title: "Fixed SSH hardening", Severity: domain.SeverityCritical, Source: domain.SourceLynis, Remediation: domain.RemediationAuto, Fixed: true},
				{ID: "fixed.002", Title: "Fixed compose hardening", Severity: domain.SeverityHigh, Source: domain.SourceCompose, Remediation: domain.RemediationReview, Fixed: true},
			},
			want: []string{"SEARCH FINDINGS", "Fixed", "✓ Fixed SSH hardening"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := readyModelForRenderRegression(t, tc.findings, tc.width, tc.height)
			if tc.prepare != nil {
				tc.prepare(m)
			}

			content := m.View().Content
			for _, want := range tc.want {
				if !strings.Contains(content, want) {
					t.Fatalf("rendered output missing %q at %dx%d:\n%s", want, tc.width, tc.height, content)
				}
			}
			assertRenderedWidthAtMost(t, content, tc.width)
		})
	}
}

func TestRenderMain_WideLayoutKeepsFilterListAndDetailSeparated(t *testing.T) {
	findings := []domain.Finding{
		{
			ID:          "lynis.AUTH-9286",
			Title:       "SSH password authentication remains enabled",
			Description: "Password logins should be disabled for internet-exposed SSH daemons.",
			HowToFix:    "Set PasswordAuthentication no and reload sshd.",
			Severity:    domain.SeverityHigh,
			Source:      domain.SourceLynis,
			Service:     "host",
			Remediation: domain.RemediationAuto,
		},
	}
	m := readyModelForRenderRegression(t, findings, 220, 44)

	output := m.renderMain()
	for _, want := range []string{"SEARCH FINDINGS", "FINDINGS", "SSH password authentication remains enabled", "HOW TO FIX"} {
		if !strings.Contains(output, want) {
			t.Fatalf("wide render missing %q:\n%s", want, output)
		}
	}
	filterIdx := strings.Index(output, "SEARCH FINDINGS")
	listIdx := strings.Index(output, "1 visible")
	detailIdx := strings.Index(output, "HOW TO FIX")
	if !(filterIdx >= 0 && listIdx > filterIdx && detailIdx > listIdx) {
		t.Fatalf("expected wide layout to render filter, list, then detail in order; indexes filter=%d list=%d detail=%d", filterIdx, listIdx, detailIdx)
	}
	if strings.Contains(output, "SEARCH FINDINGSFINDINGS") {
		t.Fatal("filter and list panel titles collapsed without spacing")
	}
	assertRenderedWidthAtMost(t, output, m.width)
}

func TestRenderModalsExposeActionableContent(t *testing.T) {
	t.Run("help switches list and detail instructions", func(t *testing.T) {
		m := readyModelForRenderRegression(t, makeTestFindings(1), 120, 32)
		listHelp := m.renderHelpModal()
		for _, want := range []string{"Help", "List mode", "Space", "Export report"} {
			if !strings.Contains(listHelp, want) {
				t.Fatalf("list help missing %q:\n%s", want, listHelp)
			}
		}

		m.mode = paneDetail
		detailHelp := m.renderHelpModal()
		for _, want := range []string{"Detail mode", "Back to list", "Scroll detail"} {
			if !strings.Contains(detailHelp, want) {
				t.Fatalf("detail help missing %q:\n%s", want, detailHelp)
			}
		}
	})

	t.Run("filter modal shows typed query and applies it", func(t *testing.T) {
		findings := []domain.Finding{
			{ID: "ssh.001", Title: "SSH password authentication", Severity: domain.SeverityHigh, Source: domain.SourceLynis, Remediation: domain.RemediationAuto},
			{ID: "tls.001", Title: "TLS package vulnerability", Severity: domain.SeverityCritical, Source: domain.SourceTrivy, Remediation: domain.RemediationManual},
		}
		m := readyModelForRenderRegression(t, findings, 120, 32)
		m.modal = modalFilter
		m.searchBox.SetValue("ssh")

		if output := m.renderFilterModal(); !strings.Contains(output, "Search findings") || !strings.Contains(output, "ssh") {
			t.Fatalf("filter modal should expose search title and query, got:\n%s", output)
		}

		got, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: "enter", Code: tea.KeyEnter}))
		mv := got.(model)
		if mv.modal != modalNone {
			t.Fatalf("enter should close filter modal, got modal %d", mv.modal)
		}
		visible := mv.visibleFindings()
		if len(visible) != 1 || visible[0].ID != "ssh.001" {
			t.Fatalf("filter query should leave only ssh.001 visible, got %#v", visible)
		}
	})

	t.Run("export modal marks current format", func(t *testing.T) {
		m := readyModelForRenderRegression(t, nil, 120, 32)
		m.exportIdx = 1
		output := m.renderExportModal()
		for _, want := range []string{"Export report", "Choose format", "CSV (spreadsheet)", "Enter export"} {
			if !strings.Contains(output, want) {
				t.Fatalf("export modal missing %q:\n%s", want, output)
			}
		}
		if !strings.Contains(output, ">") {
			t.Fatalf("export modal should mark the selected format with a cursor:\n%s", output)
		}
	})

	t.Run("fix result modal includes result and close contract", func(t *testing.T) {
		m := readyModelForRenderRegression(t, nil, 120, 32)
		m.fixResult = "✓ Hardened SSH"
		output := m.renderFixResultModal()
		for _, want := range []string{"Fix result", "✓ Hardened SSH", "Press any key to close"} {
			if !strings.Contains(output, want) {
				t.Fatalf("fix result modal missing %q:\n%s", want, output)
			}
		}
	})
}

func TestView_ModalOverlayTakesPrecedenceOverDetailAndKeys(t *testing.T) {
	findings := []domain.Finding{
		{ID: "modal.001", Title: "Finding behind modal", Severity: domain.SeverityHigh, Source: domain.SourceLynis, Remediation: domain.RemediationAuto},
	}
	m := readyModelForRenderRegression(t, findings, 120, 32)
	m.mode = paneDetail
	m.updateDetailViewport()
	m.modal = modalExport
	m.exportIdx = 0
	m.viewport.GotoBottom()
	beforeOffset := m.viewport.YOffset()

	content := m.View().Content
	for _, want := range []string{"Export report", "Choose format", "JSON (full data)", "CSV (spreadsheet)"} {
		if !strings.Contains(content, want) {
			t.Fatalf("modal overlay missing %q:\n%s", want, content)
		}
	}

	got, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: "j", Code: tea.KeyDown}))
	mv := got.(model)
	if mv.modal != modalExport {
		t.Fatalf("detail key should be dispatched to active export modal, got modal %d", mv.modal)
	}
	if mv.exportIdx != 1 {
		t.Fatalf("j should move export modal selection to CSV, got exportIdx %d", mv.exportIdx)
	}
	if gotOffset := mv.viewport.YOffset(); gotOffset != beforeOffset {
		t.Fatalf("detail viewport moved while modal was active: got offset %d, want %d", gotOffset, beforeOffset)
	}
}

func TestUpdate_CtrlASelectsOnlyBatchFixableVisibleFindings(t *testing.T) {
	findings := []domain.Finding{
		{ID: "auto.001", Title: "Automatic fix", Severity: domain.SeverityHigh, Source: domain.SourceLynis, Remediation: domain.RemediationAuto},
		{ID: "review.001", Title: "Review fix", Severity: domain.SeverityMedium, Source: domain.SourceCompose, Remediation: domain.RemediationReview},
		{ID: "manual.001", Title: "Manual guidance", Severity: domain.SeverityLow, Source: domain.SourceTrivy, Remediation: domain.RemediationManual},
		{ID: "unavailable.001", Title: "No fix", Severity: domain.SeverityCritical, Source: domain.SourceTrivy, Remediation: domain.RemediationUnavailable},
	}
	m := readyModelForRenderRegression(t, findings, 120, 32)

	got, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: "ctrl+a"}))
	mv := got.(model)

	if !mv.selectedSet["auto.001"] || !mv.selectedSet["review.001"] {
		t.Fatalf("ctrl+a should select automatic and review fixes, got %#v", mv.selectedSet)
	}
	if mv.selectedSet["manual.001"] || mv.selectedSet["unavailable.001"] || len(mv.selectedSet) != 2 {
		t.Fatalf("ctrl+a should not select manual or unavailable findings for batch fix, got %#v", mv.selectedSet)
	}
	if strings.Contains(mv.renderMain(), "4 selected") {
		t.Fatal("selection footer counted non-batch-fixable findings")
	}
}

func TestUpdate_FixProgressModalBlocksDismissalKeys(t *testing.T) {
	m := readyModelForRenderRegression(t, makeTestFindings(1), 120, 32)
	m.modal = modalFixProgress
	m.fixProgress = 1
	m.fixProgressTotal = 2
	m.fixProgressLabel = "lynis.AUTH-9286"

	got, cmd := m.Update(tea.KeyPressMsg(tea.Key{Text: "q", Code: 'q'}))
	mv := got.(model)
	if cmd != nil {
		t.Fatal("fix progress modal should block commands while fixes are running")
	}
	if mv.modal != modalFixProgress {
		t.Fatalf("q should not dismiss fix progress modal, got modal %d", mv.modal)
	}
	output := mv.renderFixProgressModal()
	for _, want := range []string{"Applying fixes", "1 / 2", "50%", "lynis.AUTH-9286"} {
		if !strings.Contains(output, want) {
			t.Fatalf("progress modal missing %q:\n%s", want, output)
		}
	}
}

func TestUpdate_FixResultModalClosesOnAnyKeyAdvertisedByPrompt(t *testing.T) {
	m := readyModelForRenderRegression(t, nil, 120, 32)
	m.modal = modalFixResult
	m.fixResult = "✓ Applied fix"
	if output := m.renderFixResultModal(); !strings.Contains(output, "Press any key to close") {
		t.Fatalf("test setup expected any-key close prompt, got:\n%s", output)
	}

	got, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: "x", Code: 'x'}))
	mv := got.(model)
	if mv.modal != modalNone {
		t.Fatalf("fix result prompt says any key closes the modal; x left modal %d active", mv.modal)
	}
}
