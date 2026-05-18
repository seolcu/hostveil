package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const (
	settingTheme = iota
	settingCount
)

type settingsModel struct {
	open      bool
	selection int
	themeName string
}

func newSettingsModel() *settingsModel {
	return &settingsModel{
		themeName: "tokyo-night",
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
		if m.selection >= settingCount {
			m.selection = settingCount - 1
		}
	case "k", "up":
		m.selection--
		if m.selection < 0 {
			m.selection = 0
		}
	case "l", "right":
		m.cycleTheme()
	case "h", "left":
		m.cycleTheme()
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

	content := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(theme.Text)).
		Render("Settings") + "\n\n"

	// Theme selector
	content += lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Theme:") + "\n"

	themes := ThemeNames()
	var themeRow []string
	for _, t := range themes {
		th := GetTheme(t)
		isSelected := t == m.themeName
		dot := "○"
		if isSelected {
			dot = "●"
		}
		entry := lipgloss.NewStyle().
			Foreground(lipgloss.Color(th.Accent)).
			Render(fmt.Sprintf("%s %s", dot, t))
		if isSelected {
			entry = lipgloss.NewStyle().
				Foreground(lipgloss.Color(th.Accent)).
				Bold(true).
				Render(fmt.Sprintf("%s %s", dot, t))
		}
		themeRow = append(themeRow, entry)
	}
	content += "  " + strings.Join(themeRow, "  ") + "\n\n"

	sep := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Border)).Render(strings.Repeat("─", dialogWidth-6))
	content += sep + "\n"

	content += lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("←/→ cycle theme  |  Esc close")

	return dialogStyle.Render(content)
}
