package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

const (
	settingTheme = iota
	settingBorders
	settingCount
)

type settingsModel struct {
	open        bool
	selection   int
	themeName   string
	showBorders bool
}

func newSettingsModel() *settingsModel {
	return &settingsModel{
		themeName:   "tokyo-night",
		showBorders: false,
	}
}

func (m *settingsModel) Toggle() {
	m.open = !m.open
}

func (m *settingsModel) IsOpen() bool { return m.open }
func (m *settingsModel) ShowBorders() bool { return m.showBorders }

func (m *settingsModel) Update(msg string) {
	if !m.open {
		return
	}
	switch msg {
	case "j", "down":
		m.selection++
		if m.selection >= settingCount {
			m.selection = settingCount - 1
		}
	case "k", "up":
		m.selection--
		if m.selection < 0 {
			m.selection = 0
		}
	case "l", "right":
		switch m.selection {
		case settingTheme:
			m.cycleTheme()
		case settingBorders:
			m.showBorders = !m.showBorders
		}
	case "h", "left":
		switch m.selection {
		case settingTheme:
			m.cycleTheme()
		case settingBorders:
			m.showBorders = !m.showBorders
		}
	case "esc", "q":
		m.open = false
	}
}

func (m *settingsModel) cycleTheme() string {
	themes := ThemeNames()
	for i, t := range themes {
		if t == m.themeName {
			m.themeName = themes[(i+1)%len(themes)]
			return m.themeName
		}
	}
	m.themeName = themes[0]
	return m.themeName
}

func (m *settingsModel) Render(theme Theme, width, height int) string {
	if !m.open {
		return ""
	}

	dialogWidth := 40
	if dialogWidth > width-4 {
		dialogWidth = width - 4
	}

	dialogStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(theme.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Width(dialogWidth).
		Padding(1, 2).
		Align(lipgloss.Left)

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(theme.Text)).
		Render("Settings")

	cursor := func(i int) string {
		if i == m.selection {
			return ">"
		}
		return " "
	}
	highlight := func(i int, s string) string {
		if i == m.selection {
			return lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Accent)).Render(s)
		}
		return s
	}

	content := title + "\n\n"
	content += fmt.Sprintf(" %s %s: %s\n", cursor(settingTheme), highlight(settingTheme, "Theme"), m.themeName)
	bordersVal := "Off"
	if m.showBorders {
		bordersVal = "On"
	}
	content += fmt.Sprintf(" %s %s: %s\n", cursor(settingBorders), highlight(settingBorders, "Borders"), bordersVal)
	content += "\n↑/↓ navigate  ←/→ toggle  Esc close"

	return dialogStyle.Render(content)
}
