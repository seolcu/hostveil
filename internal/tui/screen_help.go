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
	maxWidth := 72
	if width >= wideWidth {
		maxWidth = 84
	}
	if dialogWidth > maxWidth {
		dialogWidth = maxWidth
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
		{"1 / 2 / 3", "Switch screens (Dashboard / Findings / Report)"},
		{"↑ / ↓ or j / k", "Move selection"},
		{"Enter or l", "Open detail / select"},
		{"Esc or h", "Back / close panel"},
		{"q", "Quit"},
	})

	content += renderSection("Findings", [][2]string{
		{"/", "Search findings"},
		{"f", "Open filter panel"},
		{"s", "Cycle sort (severity → source → title)"},
		{"r", "Reset filters"},
		{"p", "Toggle fix preview (on fixable findings)"},
		{"a", "Apply fix (from fix preview)"},
	})

	content += renderSection("Report", [][2]string{
		{"j / k", "Select export format"},
		{"Enter", "Export to file"},
	})

	content += renderSection("General", [][2]string{
		{"?", "Toggle this help"},
		{"s", "Settings (Dashboard/Report) / Sort (Findings)"},
		{"h (Dashboard)", "Host triage (filter to host scope)"},
	})

	content += lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("Press ? or Esc to close")

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
