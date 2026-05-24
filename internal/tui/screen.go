package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

func renderHeader(t Theme, width int) string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(t.Text)).
		Render("hostveil " + Version)
	return lipgloss.NewStyle().
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1).
		Width(width).
		Render(title)
}

func renderOverview(t Theme, r *domain.ScanResult, width int) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Score: %d/100", r.Score))
	parts = append(parts, fmt.Sprintf("Findings: %d", r.TotalFindings()))

	fixable := 0
	for _, f := range r.Findings {
		if f.IsFixable() {
			fixable++
		}
	}
	parts = append(parts, fmt.Sprintf("Fixable: %d", fixable))

	line := strings.Join(parts, "  │  ")
	return lipgloss.NewStyle().
		Width(width).
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1).
		Foreground(lipgloss.Color(t.TextMuted)).
		Render(line)
}

func renderFindingsList(t Theme, findings []domain.Finding, selected, width, height int) string {
	if len(findings) == 0 {
		return lipgloss.NewStyle().
			Width(width).
			Height(height).
			Foreground(lipgloss.Color(t.TextMuted)).
			Align(lipgloss.Center).
			Render("No findings")
	}

	var lines []string
	for i, f := range findings {
		if i >= height {
			break
		}
		cursor := " "
		if i == selected {
			cursor = ">"
		}
		icon := severityIcon(f.Severity)
		sevColor := severityColor(f.Severity, t)

		id := shortenID(f.ID)
		title := truncate(f.Title, width-10)
		if i == selected {
			title = lipgloss.NewStyle().Bold(true).Render(title)
		}

		sev := lipgloss.NewStyle().Foreground(lipgloss.Color(sevColor)).Render(icon)
		rem := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(shortRem(f.Remediation))

		line := fmt.Sprintf("%s %s %s %s %s", cursor, sev, id, title, rem)
		if i == selected {
			line = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Render(line)
		}
		lines = append(lines, "  "+line)
	}
	content := strings.Join(lines, "\n")
	return lipgloss.NewStyle().
		Width(width).
		Height(height).
		Padding(0, 1).
		Render(content)
}

func renderDetail(t Theme, f *domain.Finding, width, height int) string {
	sevColor := severityColor(f.Severity, t)
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(sevColor)).
		Render(f.Title)

	sev := lipgloss.NewStyle().
		Foreground(lipgloss.Color(sevColor)).
		Render(strings.ToUpper(f.Severity.String()))
	rem := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.TextMuted)).
		Render(f.Remediation.Label())

	var b strings.Builder
	b.WriteString(title + "\n\n")
	b.WriteString(sev + " · " + rem + "\n\n")
	if f.Description != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Description:") + "\n")
		b.WriteString(truncate(f.Description, width-4) + "\n\n")
	}
	if f.HowToFix != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Render("How to fix:") + "\n")
		b.WriteString(truncate(f.HowToFix, width-4) + "\n")
	}
	if len(f.Evidence) > 0 {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Evidence:") + "\n")
		for k, v := range f.Evidence {
			b.WriteString(fmt.Sprintf("  %s: %s\n", k, truncate(v, width-8)))
		}
	}
	content := b.String()

	return lipgloss.NewStyle().
		Width(width).
		Height(height).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1).
		Render(content)
}

func renderSettings(t Theme, themes []Theme, cursor int, width, height int) string {
	var items []string
	for i, th := range themes {
		mark := "  "
		if i == cursor {
			mark = "> "
		}
		preview := lipgloss.NewStyle().Width(8).Render(
			strings.Repeat(" ", 2) +
				lipgloss.NewStyle().Background(lipgloss.Color(th.Critical)).Render(" ") +
				lipgloss.NewStyle().Background(lipgloss.Color(th.High)).Render(" ") +
				lipgloss.NewStyle().Background(lipgloss.Color(th.Medium)).Render(" ") +
				lipgloss.NewStyle().Background(lipgloss.Color(th.Low)).Render(" ") +
				lipgloss.NewStyle().Background(lipgloss.Color(th.Accent)).Render(" "))
		line := mark + th.Name + "  " + preview
		if i == cursor {
			line = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Render(line)
		}
		items = append(items, "  "+line)
	}
	items = append(items, "", "  ↑/k up · ↓/j down · Enter select · Esc close")

	body := lipgloss.NewStyle().
		Width(width/2).
		Height(height/2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(1, 2).
		Render(strings.Join(items, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, body)
}

func severityIcon(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical:
		return "■"
	case domain.SeverityHigh:
		return "◆"
	case domain.SeverityMedium:
		return "●"
	case domain.SeverityLow:
		return "▸"
	default:
		return "·"
	}
}

func severityColor(s domain.Severity, t Theme) string {
	switch s {
	case domain.SeverityCritical:
		return t.Critical
	case domain.SeverityHigh:
		return t.High
	case domain.SeverityMedium:
		return t.Medium
	case domain.SeverityLow:
		return t.Low
	default:
		return t.TextMuted
	}
}

func shortenID(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if len(last) > 12 {
			return last[:12] + "…"
		}
		return last
	}
	return id
}

func shortRem(r domain.RemediationKind) string {
	switch r {
	case domain.RemediationAuto:
		return "A"
	case domain.RemediationReview:
		return "R"
	case domain.RemediationUnavailable:
		return "U"
	case domain.RemediationManual:
		return "M"
	default:
		return "?"
	}
}

func truncate(s string, n int) string {
	if n <= 1 {
		return "…"
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

func lineCount(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}
