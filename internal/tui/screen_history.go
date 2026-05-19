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
	if width < 20 {
		return "Terminal too narrow"
	}

	if width < 40 {
		return m.renderMiniReport(r, theme, width)
	}

	cardStyle := lipgloss.NewStyle().
		Width(width - 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	cardWidth := width - 4

	// Card 1: Current scan summary
	var axisRows []string

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Current scan summary")
	axisRows = append(axisRows, title)
	axisRows = append(axisRows, "")

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

	// Card 3: Export options
	var exportRows []string
	exportTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Accent)).Render("Export report")
	exportRows = append(exportRows, exportTitle)
	exportRows = append(exportRows, "")
	exportFmts := []string{"JSON", "SARIF", "Markdown", "HTML"}
	for _, f := range exportFmts {
		exportRows = append(exportRows, fmt.Sprintf("  · %s", f))
	}
	exportRows = append(exportRows, "")
	exportRows = append(exportRows, "  Press s to open Settings for export")
	card3 := "\n" + cardStyle.Render(lipgloss.JoinVertical(lipgloss.Left, exportRows...))

	// Card 4: Info messages and warnings
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
	if len(r.Metadata.Warnings) > 0 {
		for _, w := range r.Metadata.Warnings {
			infoLines = append(infoLines, fmt.Sprintf("  ⚠ %s", w))
		}
	}
	card4 := ""
	if len(infoLines) > 0 {
		card4 = "\n" + cardStyle.Render(lipgloss.JoinVertical(lipgloss.Left, infoLines...))
	}

	content := card1 + card2 + card3 + card4

	style := lipgloss.NewStyle().
		Width(width).
		Padding(0, 1)

	return style.Render(content)
}

func (m *historyModel) renderMiniReport(r *domain.ScanResult, theme Theme, width int) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	findings := r.TotalFindings()

	gradeColor := theme.Critical
	if score >= 50 {
		gradeColor = theme.Medium
	}
	if score >= 80 {
		gradeColor = theme.Success
	}

	line1 := lipgloss.NewStyle().Bold(true).Render("Report")
	line2 := lipgloss.JoinHorizontal(lipgloss.Center,
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score %d/%d", score, 100)),
		" · ",
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(grade),
	)
	line3 := fmt.Sprintf("%d findings  |  s Settings for export", findings)

	style := lipgloss.NewStyle().Width(width).Padding(0, 1)
	return style.Render(line1 + "\n" + line2 + "\n" + line3)
}
