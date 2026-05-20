package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

type LayoutMode int

const (
	LayoutMini LayoutMode = iota
	LayoutCompact
	LayoutMedium
	LayoutWide
	LayoutUltraWide
)

func layoutMode(w, h int) LayoutMode {
	switch {
	case w >= 180 && h >= 45:
		return LayoutUltraWide
	case w >= 120 && h >= 35:
		return LayoutWide
	case w >= 80 && h >= 24:
		return LayoutMedium
	case w >= 50 && h >= 16:
		return LayoutCompact
	default:
		return LayoutMini
	}
}

func contentHeight(totalHeight int) int {
	if totalHeight < 6 {
		return 0
	}
	return totalHeight - 4
}

func renderCard(title, body string, theme Theme, width, height int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(theme.Text))

	content := titleStyle.Render(title)
	if body != "" {
		content += "\n" + body
	}

	rendered := style.Render(content)
	if height > 0 {
		rendered = fillHeight(rendered, height)
	}
	return rendered
}

func fillHeight(content string, targetHeight int) string {
	lines := strings.Count(content, "\n") + 1
	if lines >= targetHeight {
		return content
	}
	return content + strings.Repeat("\n", targetHeight-lines)
}

func truncateWidth(s string, maxWidth int) string {
	runes := []rune(s)
	if len(runes) <= maxWidth {
		return s
	}
	return string(runes[:maxWidth-1]) + "…"
}

func truncatePathForWidth(path string, maxWidth int) string {
	if maxWidth < 8 {
		return "…"
	}
	if lipgloss.Width(stripANSI(path)) <= maxWidth {
		return path
	}

	// Try filename only
	parts := strings.Split(path, "/")
	filename := parts[len(parts)-1]
	if lipgloss.Width(filename)+4 <= maxWidth {
		return ".../" + filename
	}

	// Try parent/filename
	if len(parts) >= 2 {
		parent := parts[len(parts)-2]
		parentFile := parent + "/" + filename
		if lipgloss.Width(parentFile)+4 <= maxWidth {
			return ".../" + parentFile
		}
	}

	// Try grandparent/parent/filename
	if len(parts) >= 3 {
		gp := parts[len(parts)-3] + "/" + parts[len(parts)-2] + "/" + filename
		if lipgloss.Width(gp)+4 <= maxWidth {
			return ".../" + gp
		}
	}

	// Fallback: ellipsis the filename itself
	maxFn := maxWidth - 4
	if maxFn < 4 {
		maxFn = 4
	}
	fn := truncateWidth(filename, maxFn)
	return ".../" + fn
}

func wrapLines(s string, w int) []string {
	if w <= 0 || s == "" {
		return []string{}
	}
	var result []string
	runes := []rune(s)
	for len(runes) > 0 {
		if len(runes) <= w {
			result = append(result, string(runes))
			break
		}
		result = append(result, string(runes[:w]))
		runes = runes[w:]
	}
	return result
}

func joinColumns(columns []string, widths []int, gap int) string {
	if len(columns) == 0 {
		return ""
	}
	if len(columns) == 1 {
		return columns[0]
	}

	colLines := make([][]string, len(columns))
	maxLines := 0
	for i, col := range columns {
		lines := strings.Split(col, "\n")
		colLines[i] = lines
		if len(lines) > maxLines {
			maxLines = len(lines)
		}
	}

	// Pad all columns to same height
	for i := range colLines {
		for len(colLines[i]) < maxLines {
			colLines[i] = append(colLines[i], strings.Repeat(" ", widths[i]))
		}
	}

	gapStr := strings.Repeat(" ", gap)
	var result []string
	for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
		var rowParts []string
		for colIdx := range columns {
			line := colLines[colIdx][lineIdx]
			// Pad to column width
			lw := visibleWidth(line)
			if lw < widths[colIdx] {
				line += strings.Repeat(" ", widths[colIdx]-lw)
			}
			rowParts = append(rowParts, line)
		}
		result = append(result, strings.Join(rowParts, gapStr))
	}

	return strings.Join(result, "\n")
}

func joinRows(rows ...string) string {
	var nonEmpty []string
	for _, r := range rows {
		if r != "" {
			nonEmpty = append(nonEmpty, r)
		}
	}
	return strings.Join(nonEmpty, "\n")
}

func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	runes := []rune(s)
	for i < len(runes) {
		if runes[i] == '\x1b' && i+1 < len(runes) && runes[i+1] == '[' {
			i += 2
			for i < len(runes) && !(runes[i] >= 'A' && runes[i] <= 'Z') && !(runes[i] >= 'a' && runes[i] <= 'z') {
				i++
			}
			if i < len(runes) {
				i++
			}
			continue
		}
		b.WriteRune(runes[i])
		i++
	}
	return b.String()
}

func visibleWidth(s string) int {
	return lipgloss.Width(s)
}

func renderLabelValue(label, value string, labelWidth int, theme Theme) string {
	labelStyle := lipgloss.NewStyle().
		Width(labelWidth).
		Foreground(lipgloss.Color(theme.TextMuted))
	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Text))
	return labelStyle.Render(label+":") + " " + valueStyle.Render(value)
}

func renderSeparator(width int, theme Theme) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Border)).
		Render(strings.Repeat("─", width))
}

func renderBar(score uint8, width int, color string) string {
	if width < 2 {
		return ""
	}
	filled := int(score) * (width - 2) / 100
	if filled > width-2 {
		filled = width - 2
	}
	bar := "["
	for i := 0; i < width-2; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	bar += "]"
	return lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(bar)
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func areaBarWidth(cardWidth int, mode LayoutMode) int {
	switch mode {
	case LayoutUltraWide:
		return clamp(cardWidth/4, 10, 18)
	case LayoutWide:
		return clamp(cardWidth/4, 8, 14)
	case LayoutMedium:
		return clamp(cardWidth/5, 6, 10)
	default:
		return 0
	}
}

func renderAreaHealthBars(r *domain.ScanResult, width int, mode LayoutMode, theme Theme) []string {
	var lines []string
	nameW := 24
	barW := areaBarWidth(width, mode)

	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		scoreColor := theme.Success
		gradeStr := "Good"
		if score < 80 {
			scoreColor = theme.Medium
			gradeStr = "Risk"
		}
		if score < 50 {
			scoreColor = theme.Critical
			gradeStr = "Critical"
		}

		label := axis.Label()
		if lipgloss.Width(label) > nameW {
			label = truncateWidth(label, nameW)
		}

		bar := renderBar(score, barW, scoreColor)
		scoreTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(scoreColor)).
			Width(4).
			Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", score))
		gradeTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(scoreColor)).
			Render(gradeStr)

		lines = append(lines, fmt.Sprintf("  %-*s %s %s %s", nameW, label, bar, scoreTag, gradeTag))
	}
	return lines
}

// ─── Dashboard height budget ──────────────────────────────────────────────

type SectionBudget struct {
	Min   int
	Ideal int
	Max   int
}

type DashboardBudget struct {
	StatusH    int
	HeroH      int
	MainH      int
	SecondaryH int
	TertiaryH  int
	WorkflowH  int
	GapH       int
}

func dashboardHeightBudget(bodyHeight int, mode LayoutMode) DashboardBudget {
	switch mode {
	case LayoutUltraWide:
		return DashboardBudget{
			StatusH:    1,
			HeroH:      clamp(bodyHeight/10, 5, 8),
			MainH:      clamp(bodyHeight/7, 8, 11),
			SecondaryH: clamp(bodyHeight/8, 7, 10),
			TertiaryH:  clamp(bodyHeight/8, 7, 10),
			WorkflowH:  clamp(bodyHeight/16, 3, 5),
			GapH:       clamp(bodyHeight/40, 1, 3),
		}
	case LayoutWide:
		return DashboardBudget{
			StatusH:    1,
			HeroH:      clamp(bodyHeight/8, 4, 6),
			MainH:      clamp(bodyHeight/4, 8, 10),
			SecondaryH: clamp(bodyHeight/4, 7, 9),
			WorkflowH:  clamp(bodyHeight/10, 3, 4),
			GapH:       1,
		}
	case LayoutMedium:
		return DashboardBudget{
			HeroH:     clamp(bodyHeight/4, 5, 7),
			MainH:     clamp(bodyHeight/4, 5, 7),
			WorkflowH: 3,
			GapH:      1,
		}
	default:
		return DashboardBudget{
			GapH: 1,
		}
	}
}

// ─── Load average formatting ─────────────────────────────────────────────

func formatLoadAvg(raw string, detailed bool) string {
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return raw
	}
	short := fmt.Sprintf("%s / %s / %s", fields[0], fields[1], fields[2])
	if detailed && len(fields) >= 5 {
		short += fmt.Sprintf("\nProcesses: %s\nLast PID: %s", fields[3], fields[4])
	}
	return short
}
