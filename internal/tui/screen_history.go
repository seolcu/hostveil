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

	cardStyle := lipgloss.NewStyle().
		Width(width - 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	cardWidth := width - 4

	// Card 1: Score summary + Axis bars
	var axisRows []string

	info := fmt.Sprintf("Score: %d (%s)  |  Findings: %d  |  Services: %d",
		r.ScoreReport.Overall, r.ScoreReport.Grade(),
		r.TotalFindings(), len(r.Metadata.Services))
	axisRows = append(axisRows, info)

	axisRows = append(axisRows, "")

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
		if cardWidth < 35 {
			labelWidth = 12
		}
		barWidth := cardWidth - labelWidth - 14
		if barWidth < 4 {
			barWidth = 4
		}
		barWidth = barWidth * 3 / 5

		labelText := axis.Label()
		if cardWidth < 35 {
			switch labelText {
			case "Excessive Permissions":
				labelText = "Permissions"
			case "Unnecessary Exposure":
				labelText = "Exposure"
			case "Update & Supply Chain":
				labelText = "Supply Chain"
			case "Sensitive Data":
				labelText = "Sensitive"
			}
		}

		label := lipgloss.NewStyle().
			Width(labelWidth).
			Render(labelText)
		bar := renderColoredBar(score, barWidth, barColor)
		scoreStr := lipgloss.NewStyle().
			Width(4).
			Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", score))

		axisRows = append(axisRows, fmt.Sprintf("  %s %s %s", label, bar, scoreStr))
	}

	card1 := cardStyle.Render(lipgloss.JoinVertical(lipgloss.Left, axisRows...))

	// Card 2: Severity summary
	var sevRows []string
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
		sevRows = append(sevRows, "  "+strings.Join(sevParts, "  "))
	}
	card2 := ""
	if len(sevRows) > 0 {
		card2 = "\n" + cardStyle.Render(lipgloss.JoinVertical(lipgloss.Left, sevRows...))
	}

	// Info messages (grouped)
	infoLines := []string{}
	if len(r.Metadata.InfoMessages) > 0 {
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
			infoLines = append(infoLines, fmt.Sprintf("  ℹ Discovered %d project(s): %s", len(projects), strings.Join(projects, ", ")))
		}
		for _, msg := range otherMsgs {
			infoLines = append(infoLines, fmt.Sprintf("  ℹ %s", msg))
		}
	}

	// Warnings
	if len(r.Metadata.Warnings) > 0 {
		for _, w := range r.Metadata.Warnings {
			infoLines = append(infoLines, fmt.Sprintf("  ⚠ %s", w))
		}
	}

	// Card 3: Info + Warnings (if any)
	card3 := ""
	if len(infoLines) > 0 {
		card3 = "\n" + cardStyle.Render(lipgloss.JoinVertical(lipgloss.Left, infoLines...))
	}

	content := card1 + card2 + card3

	style := lipgloss.NewStyle().
		Width(width).
		Padding(0, 1)

	return style.Render(content)
}
