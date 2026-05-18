package tui

import (
	"fmt"

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

	dialogWidth := 64
	if dialogWidth > width-4 {
		dialogWidth = width - 4
	}

	dialogStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(theme.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Width(dialogWidth).
		Padding(1, 2)

	content := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Keyboard Shortcuts") + "\n\n"

	sections := []struct {
		title string
		keys  [][2]string
	}{
		{"Navigation", [][2]string{
			{"Tab / 1,2,3", "Switch screens"},
			{"↑/↓ or j/k", "Navigate list"},
			{"Enter or l", "Open detail"},
			{"h or ←", "Back to list"},
			{"q or Esc", "Quit / Close"},
		}},
		{"Filters", [][2]string{
			{"s", "Cycle severity filter"},
			{"x", "Cycle source filter"},
			{"c", "Cycle scope filter"},
			{"v", "Cycle service filter"},
			{"m", "Cycle remediation filter"},
			{"o", "Cycle sort mode"},
			{"R", "Reset all filters"},
		}},
		{"Actions", [][2]string{
			{"/", "Search findings"},
			{"f", "Trigger fix (when available)"},
			{"h", "Host triage (Overview)"},
			{"S", "Settings modal"},
			{"?", "Toggle this help"},
		}},
	}

	for _, sec := range sections {
		content += lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.Accent)).
			Render(sec.title) + "\n"
		for _, kv := range sec.keys {
			content += fmt.Sprintf("  %-20s %s\n", kv[0], kv[1])
		}
		content += "\n"
	}

	content += lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("Press ? or Esc to close")

	return dialogStyle.Render(content)
}
