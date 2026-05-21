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

	innerW := dialogWidth - 6 // inner width after border(2) + padding(1,2)
	if innerW < 10 {
		innerW = 10
	}

	dialogStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(theme.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Width(dialogWidth).
		Padding(1, 2)

	sep := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Border)).Render(strings.Repeat("─", innerW))

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

	renderCompactSection := func(title string, keys [][2]string) string {
		var b strings.Builder
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Accent)).Render(title) + "\n")
		for _, kv := range keys {
			kStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color(theme.TextBright)).
				Width(16)
			vStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color(theme.Text))
			b.WriteString(fmt.Sprintf("  %s %s\n", kStyle.Render(kv[0]), vStyle.Render(kv[1])))
		}
		b.WriteString("\n")
		return b.String()
	}

	maxContentH := height - 8 // leave room for border + overlay margins

	var content string

	switch {
	case maxContentH >= 38:
		// Full: 4 sections
		content = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Keyboard Shortcuts") + "\n\n"

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

	case maxContentH >= 22:
		// Compact: condensed sections with shorter descriptions
		content = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Keyboard Shortcuts") + "\n\n"

		content += renderCompactSection("Navigation", [][2]string{
			{"1/2/3", "Switch screens"},
			{"j/k", "Move"},
			{"Enter", "Open detail"},
			{"Esc/h", "Back"},
			{"q", "Quit"},
		})

		content += renderCompactSection("Findings", [][2]string{
			{"/", "Search"},
			{"f", "Filter panel"},
			{"s", "Cycle sort"},
			{"r", "Reset"},
			{"p", "Fix preview"},
			{"a", "Apply fix"},
		})

		content += renderCompactSection("Report", [][2]string{
			{"j/k", "Select format"},
			{"Enter", "Export"},
		})

		content += renderCompactSection("General", [][2]string{
			{"?", "Help"},
			{"s", "Settings"},
			{"h", "Host triage"},
		})

	default:
		// Minimal: inline grouped keys
		content = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Keyboard Shortcuts") + "\n\n"

		groups := []struct {
			title string
			keys  string
		}{
			{"Nav", "1/2/3  j/k  Enter  Esc  q"},
			{"Findings", "/  f  s  r  p  a"},
			{"Report", "j/k  Enter"},
			{"General", "?  s  h"},
		}
		for _, g := range groups {
			content += fmt.Sprintf("  %s: %s\n",
				lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Accent)).Render(g.title),
				lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Text)).Render(g.keys))
		}
		content += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("Resize terminal for full help")
	}

	content += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("Press ? or Esc to close")

	return dialogStyle.Render(content)
}
