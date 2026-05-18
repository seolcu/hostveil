package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

type historyModel struct {
	scroll int
}

func (m *historyModel) render(r *domain.ScanResult, theme Theme, width, height int) string {
	if width < 40 {
		return "Terminal too narrow"
	}

	style := lipgloss.NewStyle().
		Width(width).
		Padding(0, 1)

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(theme.Text)).
		Render("Scan History")

	info := fmt.Sprintf("Score: %d (%s)  |  Findings: %d  |  Services: %d",
		r.ScoreReport.Overall, r.ScoreReport.Grade(),
		r.TotalFindings(), len(r.Metadata.Services))

	content := title + "\n" + info + "\n\n"

	// Axis scores with bars
	content += "Axis Scores:\n"
	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		barColor := theme.Success
		if score < 80 {
			barColor = theme.Medium
		}
		if score < 50 {
			barColor = theme.Critical
		}

		label := fmt.Sprintf("%-22s", axis.Label())
		bar := RenderBar(score, width-len(label)-10)

		styledBar := lipgloss.NewStyle().Foreground(lipgloss.Color(barColor)).Render(bar)
		content += fmt.Sprintf("  %s %s %3d\n", label, styledBar, score)
	}

	// Severity summary
	content += "\nFindings:\n"
	for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		count := r.FindingsBySeverity(sev)
		if count > 0 {
			color := sev.Color()
			content += fmt.Sprintf("  %s: %d\n",
				lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(sev.String()),
				count,
			)
		}
	}

	// Info messages (summarized)
	if len(r.Metadata.InfoMessages) > 0 {
		content += "\nInfo:\n"
		var projects []string
		var otherMsgs []string
		for _, msg := range r.Metadata.InfoMessages {
			trimmed := strings.TrimPrefix(msg, "Discovered project: ")
			if trimmed != msg {
				parts := strings.SplitN(trimmed, " at ", 2)
				if len(parts) >= 1 && parts[0] != "" {
					projects = append(projects, parts[0])
				}
			} else {
				otherMsgs = append(otherMsgs, msg)
			}
		}
		if len(projects) > 0 {
			content += fmt.Sprintf("  ℹ Discovered %d project(s): %s\n", len(projects), strings.Join(projects, ", "))
		}
		for _, msg := range otherMsgs {
			content += fmt.Sprintf("  ℹ %s\n", msg)
		}
	}

	// Warnings
	if len(r.Metadata.Warnings) > 0 {
		content += "\nWarnings:\n"
		for _, w := range r.Metadata.Warnings {
			content += fmt.Sprintf("  ⚠ %s\n", w)
		}
	}

	return style.Render(content)
}
