package tui

import (
	"testing"

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
