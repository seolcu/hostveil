package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type settingsModel struct {
	open         bool
	themeName    string
	adapterNames []string
}

func newSettingsModel() *settingsModel {
	return &settingsModel{
		themeName: "tokyo-night",
	}
}

func (m *settingsModel) SetAdapters(names []string) {
	m.adapterNames = names
}

func (m *settingsModel) Toggle() {
	m.open = !m.open
}

func (m *settingsModel) IsOpen() bool { return m.open }

func (m *settingsModel) Update(msg string) {
	if !m.open {
		return
	}
	switch msg {
	case "j", "down":
		m.cycleTheme(1)
	case "k", "up":
		m.cycleTheme(-1)
	case "l", "right":
		m.cycleTheme(1)
	case "h", "left":
		m.cycleTheme(-1)
	case "esc", "q":
		m.open = false
	}
}

func (m *settingsModel) cycleTheme(direction int) {
	themes := ThemeNames()
	for i, t := range themes {
		if t == m.themeName {
			if direction > 0 {
				m.themeName = themes[(i+1)%len(themes)]
			} else {
				m.themeName = themes[(i-1+len(themes))%len(themes)]
			}
			return
		}
	}
	m.themeName = themes[0]
}

func (m *settingsModel) Render(theme Theme, width, height int) string {
	if !m.open {
		return ""
	}

	dialogWidth := 44
	if dialogWidth > width-4 {
		dialogWidth = width - 4
	}
	if dialogWidth < 36 {
		dialogWidth = 36
	}

	dialogStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(theme.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Width(dialogWidth).
		Padding(1, 2).
		Align(lipgloss.Left)

	innerW := dialogWidth - 6
	if innerW < 10 {
		innerW = 10
	}

	surfaceBg := lipgloss.NewStyle().Background(lipgloss.Color(theme.Surface))

	var contentParts []string

	addLine := func(text string, opts ...lipgloss.Style) {
		style := surfaceBg.Width(innerW)
		for _, o := range opts {
			style = style.Inherit(o)
		}
		contentParts = append(contentParts, style.Render(text))
	}

	// Title
	addLine("Settings",
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)))
	addLine("")

	// Theme selector (2-column grid)
	addLine("Theme:",
		lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))

	themes := ThemeNames()
	colWidth := (dialogWidth - 6) / 2
	for i := 0; i < len(themes); i += 2 {
		var rowEntries []string
		for j := 0; j < 2; j++ {
			idx := i + j
			if idx >= len(themes) {
				rowEntries = append(rowEntries, strings.Repeat(" ", colWidth))
				continue
			}
			t := themes[idx]
			th := GetTheme(t)
			isSelected := t == m.themeName
			dot := "○"
			prefix := " "
			if isSelected {
				dot = "●"
				prefix = "❯"
			}
			entry := lipgloss.NewStyle().
				Foreground(lipgloss.Color(th.Accent)).
				Background(lipgloss.Color(theme.Surface)).
				Width(colWidth).
				Render(fmt.Sprintf("%s%s %s", prefix, dot, t))
			if isSelected {
				entry = lipgloss.NewStyle().
					Foreground(lipgloss.Color(th.Accent)).
					Bold(true).
					Background(lipgloss.Color(theme.Surface)).
					Width(colWidth).
					Render(fmt.Sprintf("%s%s %s", prefix, dot, t))
			}
			rowEntries = append(rowEntries, entry)
		}
		row := "  " + lipgloss.JoinHorizontal(lipgloss.Center, rowEntries...)
		contentParts = append(contentParts, surfaceBg.Width(innerW).Render(row))
	}

	addLine("")

	// Adapters section
	addLine("Adapters:",
		lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))

	if len(m.adapterNames) > 0 {
		for _, name := range m.adapterNames {
			addLine("  ● "+name,
				lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Success)))
		}
	} else {
		addLine("  · none detected",
			lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))
	}

	addLine("")

	addLine("j/k or ←/→ change theme  |  Esc close",
		lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))

	return dialogStyle.Render(strings.Join(contentParts, "\n"))
}
