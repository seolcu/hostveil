package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

func renderHistoryPanel(r *domain.ScanResult, theme Theme, width, height int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Padding(0, 1)

	out := "History\n\n"

	out += fmt.Sprintf("Current Score: %d (%s)\n", r.ScoreReport.Overall, r.ScoreReport.Grade())
	out += fmt.Sprintf("Total Findings: %d\n", r.TotalFindings())
	out += fmt.Sprintf("Services: %d\n\n", len(r.Metadata.Services))

	out += "Axis Scores:\n"
	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		bar := RenderBar(score, 20)
		out += fmt.Sprintf("  %-25s %3d %s\n", axis.Label(), score, bar)
	}

	return style.Render(out)
}


