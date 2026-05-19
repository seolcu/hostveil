package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type helpModel struct {
	show bool
}

func (m *helpModel) Toggle() { m.show = !m.show }

func (m *helpModel) Render(theme Theme, width, height int) string {
	if !m.show {
		return ""
	}

	dialogWidth := width - 8
	if dialogWidth > 72 {
		dialogWidth = 72
	}
	if dialogWidth < 40 {
		dialogWidth = 40
	}

	dialogStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(theme.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Width(dialogWidth).
		Padding(1, 2)

	content := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Keyboard Shortcuts") + "\n\n"

	sep := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Border)).Render(strings.Repeat("─", dialogWidth-6))

	renderSection := func(title string, keys [][2]string) string {
		var b strings.Builder
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Accent)).Render(title) + "\n")
		b.WriteString(sep + "\n")
		for _, kv := range keys {
			kStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color(theme.TextBright)).
				Width(20)
			vStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color(theme.Text))
			b.WriteString(fmt.Sprintf("  %s %s\n", kStyle.Render(kv[0]), vStyle.Render(kv[1])))
		}
		b.WriteString("\n")
		return b.String()
	}

	content += renderSection("Navigation", [][2]string{
		{"1 / 2 / 3", "Switch screens (Overview / Findings / History)"},
		{"↑ / ↓ or j / k", "Navigate list"},
		{"Enter or → or l", "Open finding detail panel"},
		{"← or h", "Back to list"},
		{"q or Esc", "Quit"},
	})

	content += renderSection("Filters", [][2]string{
		{"s", "Cycle severity filter (all → critical → high → …)"},
		{"x", "Cycle source filter"},
		{"c", "Cycle scope filter"},
		{"v", "Cycle service filter"},
		{"m", "Cycle remediation filter"},
		{"o", "Cycle sort mode (severity → source → title)"},
		{"R", "Reset all filters"},
	})

	content += renderSection("Actions", [][2]string{
		{"/", "Search findings"},
		{"f", "Toggle fix preview (on fixable findings)"},
		{"h (Overview)", "Host triage (filter to host scope)"},
		{"S", "Settings modal"},
		{"?", "Toggle this help"},
	})

	content += lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("Press ? or Esc to close")

	// Count estimated visible lines (border 2 top + 2 bottom + padding 2 = 6 overhead)
	contentLines := strings.Count(content, "\n") + 1
	totalLines := contentLines + 6
	maxLines := height - 2
	if totalLines > maxLines {
		hidden := totalLines - maxLines
		content += "\n\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.Medium)).
			Render(fmt.Sprintf("▼ %d line(s) hidden — resize terminal", hidden))
	}

	return dialogStyle.Render(content)
}
