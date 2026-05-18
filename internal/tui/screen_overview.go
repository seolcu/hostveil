package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

func renderOverviewPanel(r *domain.ScanResult, theme Theme, width, height int) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	total := r.TotalFindings()

	scoreStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Accent)).
		Bold(true).
		Width(width / 3).
		Align(lipgloss.Center).
		Padding(1)

	scoreBlock := scoreStyle.Render(fmt.Sprintf("Score: %d\n%s\n", score, grade))

	sevStyle := lipgloss.NewStyle().
		Width(width / 3).
		Padding(0, 1)

	sevBlock := sevStyle.Render(formatSeverityCounts(r))

	infoStyle := lipgloss.NewStyle().
		Width(width / 3).
		Padding(0, 1)

	infoBlock := infoStyle.Render(fmt.Sprintf("%d findings\n%d services", total, len(r.Metadata.Services)))

	return lipgloss.JoinHorizontal(lipgloss.Top, scoreBlock, sevBlock, infoBlock)
}

func formatSeverityCounts(r *domain.ScanResult) string {
	out := ""
	for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		count := r.FindingsBySeverity(sev)
		if count > 0 {
			out += fmt.Sprintf("%s: %d\n", sev.String(), count)
		}
	}
	return out
}
