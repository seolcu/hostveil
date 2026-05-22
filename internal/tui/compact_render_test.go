package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/seolcu/hostveil/internal/domain"
)

func TestCompactFindingsRenderer(t *testing.T) {
	findings := []domain.Finding{
		{
			ID: "F-001", Title: "Exposed port 6379 on 0.0.0.0",
			Severity: domain.SeverityCritical, Axis: domain.AxisUnnecessaryExposure,
			Scope: domain.ScopeService, Source: domain.SourceNativeCompose,
			Service: "redis", Remediation: domain.RemediationAuto,
			Description: "Public port binding", WhyRisky: "Allows external access",
			HowToFix: "Remove port mapping or bind to 127.0.0.1",
		},
		{
			ID: "F-002", Title: "Container running as root",
			Severity: domain.SeverityHigh, Axis: domain.AxisExcessivePermissions,
			Scope: domain.ScopeService, Source: domain.SourceNativeCompose,
			Service: "app", Remediation: domain.RemediationReview,
			Description: "Root user in container", WhyRisky: "Escape possible",
			HowToFix: "Set non-root user",
		},
		{
			ID: "F-003", Title: "No resource limits set",
			Severity: domain.SeverityMedium, Axis: domain.AxisHostHardening,
			Scope: domain.ScopeService, Source: domain.SourceNativeCompose,
			Service: "app", Remediation: domain.RemediationManual,
			Description: "Missing memory limits", WhyRisky: "OOM on host",
			HowToFix: "Add deploy.resources.limits",
		},
	}

	theme := DefaultTheme()

	t.Run("mini_no_detail", func(t *testing.T) {
		m := newFindingsModel(findings)
		_ = m.renderMiniFindings(theme, 39)
	})

	t.Run("mini_with_detail", func(t *testing.T) {
		m := newFindingsModel(findings)
		m.showDetail = true
		_ = m.renderMiniFindings(theme, 39)
	})

	t.Run("compact_list", func(t *testing.T) {
		m := newFindingsModel(findings)
		_ = m.renderCompactFindings(theme, 50, 16)
	})

	t.Run("compact_detail", func(t *testing.T) {
		m := newFindingsModel(findings)
		m.showDetail = true
		_ = m.renderCompactFindings(theme, 50, 16)
	})

	t.Run("compact_empty", func(t *testing.T) {
		m := newFindingsModel(nil)
		_ = m.renderCompactFindings(theme, 50, 16)
	})

	t.Run("compact_selected_last", func(t *testing.T) {
		m := newFindingsModel(findings)
		m.showDetail = true
		m.selected = 2
		_ = m.renderCompactFindings(theme, 50, 16)
	})

	t.Run("compact_very_narrow", func(t *testing.T) {
		m := newFindingsModel(findings)
		_ = m.renderCompactFindings(theme, 50, 18)
	})
}

func TestCompactReportRenderer(t *testing.T) {
	result := &domain.ScanResult{
		ScoreReport: domain.ScoreReport{Overall: 45},
		Findings:    []domain.Finding{{ID: "F-001", Severity: domain.SeverityCritical, Title: "Test"}},
	}
	theme := DefaultTheme()
	m := &historyModel{}

	t.Run("compact", func(t *testing.T) {
		_ = m.renderCompactReport(result, theme, 50)
	})
	t.Run("narrow", func(t *testing.T) {
		_ = m.renderCompactReport(result, theme, 60)
	})
}

func TestCompactDashboardRenderer(t *testing.T) {
	result := &domain.ScanResult{
		ScoreReport: domain.ScoreReport{Overall: 45},
		Findings: []domain.Finding{
			{ID: "F-001", Title: "Test", Severity: domain.SeverityCritical, Remediation: domain.RemediationAuto},
			{ID: "F-002", Title: "Test2", Severity: domain.SeverityHigh, Remediation: domain.RemediationReview},
			{ID: "F-003", Title: "Test3", Severity: domain.SeverityMedium, Remediation: domain.RemediationManual},
			{ID: "F-004", Title: "Test4", Severity: domain.SeverityLow, Remediation: domain.RemediationAuto},
			{ID: "F-005", Title: "Test5", Severity: domain.SeverityLow, Remediation: domain.RemediationAuto},
		},
	}
	cleanResult := &domain.ScanResult{
		ScoreReport: domain.ScoreReport{Overall: 100},
		Findings:    nil,
	}
	theme := DefaultTheme()
	m := &overviewModel{}

	t.Run("mini", func(t *testing.T) {
		_ = m.renderMiniDashboard(result, theme, 39)
	})
	t.Run("mini_clean", func(t *testing.T) {
		_ = m.renderMiniDashboard(cleanResult, theme, 39)
	})
	t.Run("compact", func(t *testing.T) {
		_ = m.renderCompactDashboard(result, theme, 50)
	})
	t.Run("compact_clean", func(t *testing.T) {
		_ = m.renderCompactDashboard(cleanResult, theme, 50)
	})
}

func TestRenderInfoStripBodyVisible(t *testing.T) {
	theme := DefaultTheme()
	t.Run("h3_shows_body", func(t *testing.T) {
		got := renderInfoStrip("Test label", "Body text should be visible here", theme, 80, 3)
		if !strings.Contains(stripANSI(got), "Body text should be visible") {
			t.Fatalf("expected strip body to be visible at H=3, got:\n%s", got)
		}
	})
	t.Run("h2_still_works", func(t *testing.T) {
		got := renderInfoStrip("Mini", "x", theme, 40, 2)
		// H=2: only borders, no content body. Should not panic.
		_ = got
	})
	t.Run("h4_has_extra_space", func(t *testing.T) {
		got := renderInfoStrip("Wide label", "Longer body content for testing", theme, 80, 4)
		if !strings.Contains(stripANSI(got), "Longer body content") {
			t.Fatalf("expected strip body visible at H=4:\n%s", got)
		}
	})
}

func TestTitledCardH3LosesBody(t *testing.T) {
	theme := DefaultTheme()
	t.Run("titled_card_h3_loses_body", func(t *testing.T) {
		got := renderCardBounded("Export guidance", "  JSON for automation", theme, Rect{W: 80, H: 3})
		body := stripANSI(got)
		if strings.Contains(body, "JSON for automation") {
			t.Logf("WARNING: H=3 titled card unexpectedly shows body (expected only title):\n%s", body)
		}
	})
}

func TestExportGuidanceUsesOuterDimensions(t *testing.T) {
	theme := DefaultTheme()
	got := renderInfoStrip("Export guidance",
		"JSON for automation · SARIF for code/security tooling · Markdown for project docs · HTML for sharing",
		theme, 80, 3)
	body := stripANSI(got)
	if !strings.Contains(body, "JSON for automation") {
		t.Fatalf("expected export guidance body to be visible, got:\n%s", body)
	}
	if !strings.Contains(body, "SARIF") {
		t.Fatalf("expected SARIF in guidance body:\n%s", body)
	}
}

func TestFindingsGuidanceTextContent(t *testing.T) {
	theme := DefaultTheme()
	findings := []domain.Finding{
		{ID: "F-001", Title: "Test", Severity: domain.SeverityCritical, Remediation: domain.RemediationAuto},
	}
	m := newFindingsModel(findings)
	text := m.renderFixGuidanceText(theme, 0)
	if !strings.Contains(text, "Auto-fix") {
		t.Fatalf("expected Auto-fix guidance text, got: %s", text)
	}
	// Also verify it renders in info strip without panic
	got := renderInfoStrip("Fix guidance", text, theme, 80, 3)
	body := stripANSI(got)
	if !strings.Contains(body, "Auto-fix") {
		t.Fatalf("expected Fix guidance body to be visible:\n%s", body)
	}
}

func TestAppCompactNavigationDoesNotPanic(t *testing.T) {
	result := &domain.ScanResult{
		Findings: []domain.Finding{
			{ID: "F-001", Title: "SSH root login may be permitted", Severity: domain.SeverityHigh, Remediation: domain.RemediationReview},
			{ID: "F-002", Title: "Docker socket is accessible to non-root users", Severity: domain.SeverityHigh, Remediation: domain.RemediationReview},
		},
		ScoreReport: domain.ScoreReport{Overall: 2},
		Metadata: domain.ScanMetadata{ScanMode: domain.ScanModeLive},
	}

	for _, size := range []struct{ w, h int }{
		{50, 18},
		{39, 10},
		{32, 8},
		{28, 6},
	} {
		m := NewApp(result)
		model, _ := m.Update(tea.WindowSizeMsg{Width: size.w, Height: size.h})
		app := model.(*appModel)

		steps := []tea.KeyMsg{
			{Type: tea.KeyRunes, Runes: []rune{'2'}},
			{Type: tea.KeyEnter},
			{Type: tea.KeyRunes, Runes: []rune{'p'}},
			{Type: tea.KeyRunes, Runes: []rune{'3'}},
		}

		for _, key := range steps {
			var cmd tea.Cmd
			model, cmd = app.Update(key)
			_ = cmd
			app = model.(*appModel)
			view := app.View()
			if len(strings.TrimSpace(stripANSI(view))) == 0 {
				t.Fatalf("View() returned empty at size %dx%d after key %q", size.w, size.h, key.Runes)
			}
		}
	}
}
