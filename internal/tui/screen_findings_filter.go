package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func naturalFilterValue(label, value string) string {
	switch {
	case value == "all":
		return "All"
	case label == "Severity":
		return naturalSeverity(value)
	case label == "Source":
		return naturalSource(value)
	case label == "Scope":
		return naturalScope(value)
	case label == "Fix":
		return naturalRemediation(value)
	default:
		return value
	}
}

func naturalSeverity(s string) string {
	switch s {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return s
}

func naturalSource(s string) string {
	switch s {
	case "native_compose":
		return "Compose"
	case "native_host":
		return "Host"
	}
	return s
}

func naturalScope(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func naturalRemediation(s string) string {
	switch s {
	case "auto":
		return "Auto"
	case "review":
		return "Review"
	case "manual":
		return "Manual"
	}
	return s
}

func (m *findingsModel) renderFilterPanel(theme Theme, panelWidth, panelHeight int) string {
	dialogWidth := 44
	if dialogWidth > panelWidth-4 {
		dialogWidth = panelWidth - 4
	}
	if dialogWidth < 36 {
		dialogWidth = 36
	}

	dialogStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(theme.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Width(dialogWidth).
		Padding(1, 2)

	var content strings.Builder
	content.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(theme.Text)).
		Render("Filters") + "\n\n")

	for i, row := range filterPanelRows {
		cursor := " "
		if i == m.filterCursor {
			cursor = "❯"
		}

		label := lipgloss.NewStyle().
			Width(12).
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(row.label + ":")

		val := row.value
		if val == "" {
			val = "all"
		}
		valDisplay := naturalFilterValue(row.label, val)
		valStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextBright))
		if i == m.filterCursor {
			valStyle = valStyle.Bold(true).Background(lipgloss.Color(theme.Card))
		}

		content.WriteString(fmt.Sprintf("%s %s %s\n", cursor, label, valStyle.Render(valDisplay)))
	}

	content.WriteString("\n")
	content.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("j/k move  ·  ←/→ cycle  ·  f/esc close  ·  r reset"))

	return dialogStyle.Render(content.String())
}

func (m *findingsModel) renderFilterBar(theme Theme, width int) string {
	var tokens []string
	if m.severityFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Severity: %s", naturalSeverity(m.severityFilter)))
	}
	if m.sourceFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Source: %s", naturalSource(m.sourceFilter)))
	}
	if m.scopeFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Scope: %s", naturalScope(m.scopeFilter)))
	}
	if m.serviceFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Service: %s", m.serviceFilter))
	}
	if m.remediationFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Fix: %s", naturalRemediation(m.remediationFilter)))
	}
	if m.sortMode != "" && m.sortMode != "severity" {
		tokens = append(tokens, fmt.Sprintf("Sort: %s ↑", m.sortMode))
	}

	info := fmt.Sprintf("%d findings", len(m.list))
	if len(tokens) > 0 {
		filterLine := strings.Join(tokens, " | ")
		if lipgloss.Width(info)+lipgloss.Width(filterLine)+7 > width {
			info += "\n" + strings.Repeat(" ", 6) + filterLine
		} else {
			info += "  |  " + filterLine
		}
	}

	if m.showSearch {
		s := "search: Type to search, Esc to cancel"
		if m.searchQuery != "" {
			s = fmt.Sprintf("search: %s█", m.searchQuery)
		}
		if lipgloss.Width(info)+lipgloss.Width(s)+7 > width {
			info += "\n" + strings.Repeat(" ", 6) + s
		} else {
			info += " | " + s
		}
	}

	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Width(width)

	return style.Render(info)
}
