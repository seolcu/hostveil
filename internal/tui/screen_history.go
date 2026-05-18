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

	content := ""

	// Score summary line
	info := fmt.Sprintf("Score: %d (%s)  |  Findings: %d  |  Services: %d",
		r.ScoreReport.Overall, r.ScoreReport.Grade(),
		r.TotalFindings(), len(r.Metadata.Services))
	content += info + "\n\n"

	// Axis scores with compact bars
	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		barColor := theme.Success
		if score < 80 {
			barColor = theme.Medium
		}
		if score < 50 {
			barColor = theme.Critical
		}

		labelWidth := 22
		barWidth := width - labelWidth - 14
		if barWidth < 4 {
			barWidth = 4
		}
		barWidth = barWidth * 3 / 5

		label := fmt.Sprintf("%-22s", axis.Label())
		bar := renderColoredBar(score, barWidth, barColor)
		scoreStr := fmt.Sprintf(" %3d", score)

		content += fmt.Sprintf("  %s %s%s\n", label, bar, scoreStr)
	}

	// Severity summary inline
	sevParts := []string{}
	for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		count := r.FindingsBySeverity(sev)
		if count > 0 {
			col := sev.Color()
			sevParts = append(sevParts,
				lipgloss.NewStyle().Foreground(lipgloss.Color(col)).Render(fmt.Sprintf("%s: %d", sev.String(), count)),
			)
		}
	}
	if len(sevParts) > 0 {
		content += "\nFindings: " + strings.Join(sevParts, "  ") + "\n"
	}

	// Info messages (grouped)
	if len(r.Metadata.InfoMessages) > 0 {
		content += "\nInfo:\n"
		var projects []string
		var otherMsgs []string
		seenProjects := make(map[string]bool)
		for _, msg := range r.Metadata.InfoMessages {
			trimmed := strings.TrimPrefix(msg, "Discovered project: ")
			if trimmed != msg {
				parts := strings.SplitN(trimmed, " at ", 2)
				if len(parts) >= 1 && parts[0] != "" {
					if !seenProjects[parts[0]] {
						projects = append(projects, parts[0])
						seenProjects[parts[0]] = true
					}
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

	style := lipgloss.NewStyle().
		Width(width).
		Padding(0, 1)

	return style.Render(content)
}
