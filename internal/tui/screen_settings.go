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

	innerW := dialogWidth - 6
	if innerW < 10 {
		innerW = 10
	}

	surfaceBg := lipgloss.NewStyle().Background(lipgloss.Color(theme.Surface))

	// ── Build content lines ─────────────────────────────────────────────────
	var lines []string

	addLine := func(text string, opts ...lipgloss.Style) {
		style := surfaceBg.Width(innerW)
		for _, o := range opts {
			style = style.Inherit(o)
		}
		lines = append(lines, style.Render(text))
	}

	// Top padding
	lines = append(lines, surfaceBg.Width(innerW).Render(""))

	// Title
	addLine("Settings",
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)))
	addLine("")

	// Theme selector
	addLine("Theme:",
		lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))

	themes := ThemeNames()
	indent := "  "
	twoCol := innerW >= 34

	if twoCol {
		colWidth := (innerW - len(indent)) / 2
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
				label := fmt.Sprintf("%s%s %s", prefix, dot, t)
				if lipgloss.Width(label) > colWidth {
					label = truncateWidth(label, colWidth)
				}
				entry := lipgloss.NewStyle().
					Foreground(lipgloss.Color(th.Accent)).
					Background(lipgloss.Color(theme.Surface)).
					Width(colWidth)
				if isSelected {
					entry = entry.Bold(true)
				}
				rowEntries = append(rowEntries, entry.Render(label))
			}
			row := indent + lipgloss.JoinHorizontal(lipgloss.Center, rowEntries...)
			lines = append(lines, surfaceBg.Width(innerW).Render(row))
		}
	} else {
		for _, t := range themes {
			th := GetTheme(t)
			isSelected := t == m.themeName
			dot := "○"
			prefix := " "
			if isSelected {
				dot = "●"
				prefix = "❯"
			}
			label := fmt.Sprintf("%s%s %s", prefix, dot, t)
			entry := lipgloss.NewStyle().
				Foreground(lipgloss.Color(th.Accent)).
				Background(lipgloss.Color(theme.Surface)).
				Width(innerW - len(indent))
			if isSelected {
				entry = entry.Bold(true)
			}
			lines = append(lines, surfaceBg.Width(innerW).Render(indent+entry.Render(label)))
		}
	}

	addLine("")

	// Adapters section
	addLine("Adapters:",
		lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))

	// ── Height-aware clipping ──────────────────────────────────────────────
	// Reserve fixed lines: title(1) + blank(1) + Theme(1) + themeRows + 
	// blank(1) + Adapters(1) + adapterLines + blank(1) + hint(1) + padding(2) + border(2)
	maxContentH := height - 8

	// Count current lines so far (title, blank, theme label, themes, blank, adapters label)
	adapterStart := len(lines)

	if len(m.adapterNames) > 0 {
		for _, name := range m.adapterNames {
			addLine("  ● "+name,
				lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Success)))
		}
	} else {
		addLine("  · none detected",
			lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))
	}

	// Truncate adapters if too tall
	if maxContentH > 0 && len(lines) > maxContentH {
		// Determine how many adapters to keep
		keepLines := lines[:adapterStart]
		remaining := maxContentH - adapterStart - 2 // reserve for hint + bottom
		if remaining < 1 {
			remaining = 1
		}
		// Keep header + at least 1 adapter
		var adapterLines []string
		for i := adapterStart; i < len(lines); i++ {
			if len(adapterLines) >= remaining {
				break
			}
			adapterLines = append(adapterLines, lines[i])
		}
		hidden := len(m.adapterNames) - len(adapterLines)
		if hidden > 0 {
			lastLine := surfaceBg.Width(innerW).Render(
				fmt.Sprintf("  · … and %d more", hidden))
			adapterLines[len(adapterLines)-1] = lastLine
		}
		lines = append(keepLines, adapterLines...)
	}

	addLine("")

	if twoCol {
		addLine("j/k or ←/→ change theme  |  Esc close",
			lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))
	} else {
		addLine("j/k change · Esc close",
			lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)))
	}

	// Bottom padding
	lines = append(lines, surfaceBg.Width(innerW).Render(""))

	content := strings.Join(lines, "\n")

	// If content still exceeds viewport, apply height cap via dialog style
	dialogStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(theme.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Width(dialogWidth).
		Padding(0, 2).
		Align(lipgloss.Left)

	return dialogStyle.Render(content)
}
