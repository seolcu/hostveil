package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

type overviewModel struct {
	scroll int
}

func severityIcon(sev domain.Severity) string {
	switch sev {
	case domain.SeverityCritical:
		return "■"
	case domain.SeverityHigh:
		return "◆"
	case domain.SeverityMedium:
		return "●"
	case domain.SeverityLow:
		return "▸"
	default:
		return "·"
	}
}

func (m *overviewModel) render(r *domain.ScanResult, theme Theme, width, height int) string {
	if width < 40 {
		return "Terminal too narrow for overview"
	}

	switch {
	case width >= 100:
		colWidth := (width - 6) / 3
		scoreCard := m.renderScoreCard(r, theme, colWidth)
		severityCard := m.renderSeverityCard(r, theme, colWidth)
		actionCard := m.renderActionCard(r, theme, colWidth)
		axisCard := m.renderAxisCard(r, theme, colWidth)
		hostCard := m.renderHostCard(r, theme, colWidth)
		metaCard := m.renderMetaCard(r, theme, colWidth)

		left := lipgloss.JoinVertical(lipgloss.Top, scoreCard, severityCard)
		middle := lipgloss.JoinVertical(lipgloss.Top, axisCard, hostCard)
		right := lipgloss.JoinVertical(lipgloss.Top, actionCard, metaCard)

		return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", middle, "  ", right)

	case width >= 60:
		colWidth := (width - 2) / 2
		scoreCard := m.renderScoreCard(r, theme, colWidth)
		severityCard := m.renderSeverityCard(r, theme, colWidth)
		actionCard := m.renderActionCard(r, theme, colWidth)
		axisCard := m.renderAxisCard(r, theme, colWidth)
		hostCard := m.renderHostCard(r, theme, colWidth)
		metaCard := m.renderMetaCard(r, theme, colWidth)

		left := lipgloss.JoinVertical(lipgloss.Top, scoreCard, severityCard, actionCard)
		right := lipgloss.JoinVertical(lipgloss.Top, axisCard, hostCard, metaCard)

		return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)

	default:
		colWidth := width - 2
		return lipgloss.JoinVertical(lipgloss.Top,
			m.renderScoreCard(r, theme, colWidth),
			m.renderSeverityCard(r, theme, colWidth),
			m.renderAxisCard(r, theme, colWidth),
			m.renderActionCard(r, theme, colWidth),
			m.renderHostCard(r, theme, colWidth),
			m.renderMetaCard(r, theme, colWidth),
		)
	}
}

func (m *overviewModel) renderScoreCard(r *domain.ScanResult, theme Theme, width int) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()

	scoreStyle := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1).
		Align(lipgloss.Center)

	gradeColor := theme.Success
	if score < 80 {
		gradeColor = theme.Medium
	}
	if score < 50 {
		gradeColor = theme.Critical
	}

	bar := renderColoredBar(uint8(score), (width-8)/2, gradeColor)

	content := lipgloss.JoinVertical(lipgloss.Center,
		lipgloss.JoinHorizontal(lipgloss.Center,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("%d", score)),
			"  ",
			lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(grade),
		),
		bar,
	)

	return scoreStyle.Render(content)
}

func (m *overviewModel) renderSeverityCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	var rows []string
	for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		count := r.FindingsBySeverity(sev)
		icon := severityIcon(sev)
		color := sev.Color()

		label := lipgloss.NewStyle().
			Foreground(lipgloss.Color(color)).
			Render(fmt.Sprintf("%s %s", icon, strings.ToUpper(sev.String())))

		spacer := width - lipgloss.Width(label) - 5
		if spacer < 1 {
			spacer = 1
		}

		num := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(color)).
			Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", count))

		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Center, label, strings.Repeat(" ", spacer), num))
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderActionCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	autoCount := 0
	reviewCount := 0
	manualCount := 0
	hostCount := 0

	for _, f := range r.Findings {
		switch f.Remediation {
		case domain.RemediationAuto:
			autoCount++
		case domain.RemediationReview:
			reviewCount++
		case domain.RemediationManual:
			manualCount++
		}
		if f.Scope == domain.ScopeHost {
			hostCount++
		}
	}

	items := []struct {
		label string
		count int
		color string
	}{
		{"Auto-fix", autoCount, theme.Success},
		{"Review", reviewCount, theme.Accent},
		{"Manual", manualCount, theme.TextMuted},
		{"Host", hostCount, theme.Medium},
	}

	var rows []string
	for _, item := range items {
		l := lipgloss.NewStyle().Foreground(lipgloss.Color(item.color)).Render(item.label)
		spacer := width - lipgloss.Width(l) - 5
		if spacer < 1 {
			spacer = 1
		}
		n := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(item.color)).Align(lipgloss.Right).Render(fmt.Sprintf("%d", item.count))
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Center, l, strings.Repeat(" ", spacer), n))
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderAxisCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	var rows []string
	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		barColor := theme.Success
		if score < 80 {
			barColor = theme.Medium
		}
		if score < 50 {
			barColor = theme.Critical
		}

		labelWidth := 22
		if width < 35 {
			labelWidth = 12
		}
		barWidth := width - labelWidth - 8
		if barWidth < 4 {
			barWidth = 4
		}
		// Reduce bar width by 40% to save space
		barWidth = barWidth * 3 / 5

		labelText := axis.Label()
		// Abbreviate labels for narrow viewports
		if width < 35 {
			switch labelText {
			case "Excessive Permissions":
				labelText = "Permissions"
			case "Unnecessary Exposure":
				labelText = "Exposure"
			case "Update & Supply Chain":
				labelText = "Supply Chain"
			case "Sensitive Data":
				labelText = "Sensitive\nData"
			}
		}
		label := lipgloss.NewStyle().
			Width(labelWidth).
			Render(labelText)

		bar := renderColoredBar(score, barWidth, barColor)

		scoreNum := lipgloss.NewStyle().
			Width(4).
			Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", score))

		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Center, label, " ", bar, " ", scoreNum))
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderHostCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	info := r.Metadata.HostRuntime
	if info == nil {
		return style.Render("No host data")
	}

	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("%-12s %s", k+":", v))
	}

	if info.Hostname != "" {
		addRow("Hostname", info.Hostname)
	}
	if info.DockerVersion != "" {
		addRow("Docker", info.DockerVersion)
	}
	if info.Uptime != "" {
		addRow("Uptime", info.Uptime)
	}
	if info.LoadAverage != "" {
		loadStr := info.LoadAverage
		fields := strings.Fields(loadStr)
		shortLoad := ""
		for i, f := range fields {
			if i >= 3 {
				break
			}
			if i > 0 {
				shortLoad += " "
			}
			shortLoad += f
		}
		if len(fields) > 0 {
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
				switch {
				case v > 2.0:
					shortLoad += " ↑"
				case v > 1.0:
					shortLoad += " →"
				}
			}
		}
		addRow("Load", shortLoad)
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderMetaCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	parts := []string{
		fmt.Sprintf("Services: %d", len(r.Metadata.Services)),
		fmt.Sprintf("Findings: %d", r.TotalFindings()),
	}
	if len(r.Metadata.Warnings) > 0 {
		parts = append(parts, fmt.Sprintf("Warnings: %d", len(r.Metadata.Warnings)))
	}
	if len(r.Metadata.InfoMessages) > 0 {
		parts = append(parts, fmt.Sprintf("Info: %d", len(r.Metadata.InfoMessages)))
	}

	return style.Render(strings.Join(parts, "  |  "))
}

func RenderBar(score uint8, width int) string {
	if width < 2 {
		return ""
	}
	filled := int(score) * width / 100
	bar := "["
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	bar += "]"
	return bar
}

func renderColoredBar(score uint8, width int, color string) string {
	bar := RenderBar(score, width)
	return lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(bar)
}
