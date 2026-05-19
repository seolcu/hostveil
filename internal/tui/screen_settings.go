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

var exportFormats = []string{"json", "sarif", "markdown", "html"}

type settingsModel struct {
	open          bool
	themeName     string
	adapterNames  []string
	exportFormat  int // index into exportFormats
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
	m.exportFormat = 0
}

func (m *settingsModel) IsOpen() bool { return m.open }

func (m *settingsModel) CurrentExportFormat() string {
	if m.exportFormat >= 0 && m.exportFormat < len(exportFormats) {
		return exportFormats[m.exportFormat]
	}
	return "json"
}

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
	case "E":
		m.exportFormat = (m.exportFormat + 1) % len(exportFormats)
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

	content := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(theme.Text)).
		Render("Settings") + "\n\n"

	// Theme selector (2-column grid)
	content += lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Theme:") + "\n"

	themes := ThemeNames()
	colWidth := (dialogWidth - 6) / 2
	for i := 0; i < len(themes); i += 2 {
		rowEntries := []string{}
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
				Width(colWidth).
				Render(fmt.Sprintf("%s%s %s", prefix, dot, t))
			if isSelected {
				entry = lipgloss.NewStyle().
					Foreground(lipgloss.Color(th.Accent)).
					Bold(true).
					Width(colWidth).
					Render(fmt.Sprintf("%s%s %s", prefix, dot, t))
			}
			rowEntries = append(rowEntries, entry)
		}
		content += "  " + lipgloss.JoinHorizontal(lipgloss.Center, rowEntries...) + "\n"
	}
	content += "\n"

	// Adapters section
	content += lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Adapters:") + "\n"
	if len(m.adapterNames) > 0 {
		for _, name := range m.adapterNames {
			content += "  " + lipgloss.NewStyle().
				Foreground(lipgloss.Color(theme.Success)).
				Render("● "+name) + "\n"
		}
	} else {
		content += "  " + lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render("· none detected") + "\n"
	}
	content += "\n"

	sep := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Border)).Render(strings.Repeat("─", dialogWidth-6))
	content += sep + "\n"

	// Export section
	content += lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Accent)).
		Render("Export Report:") + "\n"
	fmtName := exportFormats[m.exportFormat]
	fmtUpper := strings.ToUpper(fmtName[:1]) + fmtName[1:]
	content += "  " + lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Text)).
		Render(fmt.Sprintf("Format: %s", fmtUpper)) + "\n"
	content += "  " + lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("E cycle format  |  e export to file") + "\n"
	content += "\n"

	sep2 := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Border)).Render(strings.Repeat("─", dialogWidth-6))
	content += sep2 + "\n"

	content += lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("j/k or ←/→ change theme  |  Esc close")

	return dialogStyle.Render(content)
}
