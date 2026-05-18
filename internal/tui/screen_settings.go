package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

const (
	settingTheme = iota
	settingBorders
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

func (m *settingsModel) Update(msg string) {
	if !m.open {
		return
	}
	switch msg {
	case "j", "down":
		m.selection++
		if m.selection > settingBorders {
			m.selection = settingBorders
		}
	case "k", "up":
		m.selection--
		if m.selection < settingTheme {
			m.selection = settingTheme
		}
	case "l", "right":
		switch m.selection {
		case settingTheme:
			m.cycleTheme()
		}
	case "h", "left":
		switch m.selection {
		case settingTheme:
			m.cycleTheme()
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
	content += fmt.Sprintf(" %s %s: %v\n", cursor(settingBorders), highlight(settingBorders, "Borders"), m.showBorders)
	content += "\n↑/↓ navigate  Esc close"

	return dialogStyle.Render(content)
}
