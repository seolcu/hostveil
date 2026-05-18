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

func (m *overviewModel) render(r *domain.ScanResult, theme Theme, width, height int) string {
	if width < 40 {
		return "Terminal too narrow for overview"
	}

	switch {
	case width >= 100:
		// 3-column layout: Score/Severity | Axis/Host | Action/Meta
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
		// 2-column layout
		colWidth := (width - 4) / 2

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
		// 1-column layout (stacked)
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
		Padding(1).
		Align(lipgloss.Center)

	gradeColor := theme.Success
	if score < 80 {
		gradeColor = theme.Medium
	}
	if score < 50 {
		gradeColor = theme.Critical
	}

	content := lipgloss.JoinVertical(lipgloss.Center,
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("%d", score)),
		lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("Overall Score"),
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(grade),
	)

	// Mini bar
	bar := RenderBar(uint8(score), width-6)
	content = lipgloss.JoinVertical(lipgloss.Center, content, bar)

	return scoreStyle.Render(content)
}

func (m *overviewModel) renderSeverityCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Findings by Severity")

	var rows []string
	for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		count := r.FindingsBySeverity(sev)
		color := sev.Color()

		label := lipgloss.NewStyle().
			Foreground(lipgloss.Color(color)).
			Width(10).
			Render(strings.ToUpper(sev.String()))

		num := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(color)).
			Width(4).
			Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", count))

		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Center, label, num))
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left,
		title,
		lipgloss.JoinVertical(lipgloss.Left, rows...),
	))
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

	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Action Queue")

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
		l := lipgloss.NewStyle().Foreground(lipgloss.Color(item.color)).Width(12).Render(item.label)
		n := lipgloss.NewStyle().Bold(true).Width(4).Align(lipgloss.Right).Render(fmt.Sprintf("%d", item.count))
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Center, l, n))
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left, title, lipgloss.JoinVertical(lipgloss.Left, rows...)))
}

func (m *overviewModel) renderAxisCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Axis Scores")

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

		label := lipgloss.NewStyle().
			Width(22).
			Render(axis.Label())

		bar := renderColoredBar(score, width-30, barColor)

		scoreNum := lipgloss.NewStyle().
			Width(4).
			Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", score))

		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Center, label, bar, scoreNum))
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left, title, lipgloss.JoinVertical(lipgloss.Left, rows...)))
}

func (m *overviewModel) renderHostCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Host Info")

	info := r.Metadata.HostRuntime
	if info == nil {
		return style.Render(lipgloss.JoinVertical(lipgloss.Left, title, "No host data"))
	}

	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("%-14s %s", k+":", v))
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
		loadLevel := ""
		fields := strings.Fields(loadStr)
		if len(fields) > 0 {
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
				switch {
				case v > 2.0:
					loadLevel = " (High)"
				case v > 1.0:
					loadLevel = " (Medium)"
				default:
					loadLevel = ""
				}
			}
		}
		// Show only 1/5/15m averages, drop process/thread counts
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
		addRow("Load", shortLoad+loadLevel)
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n")))
}

func (m *overviewModel) renderMetaCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	svcs := len(r.Metadata.Services)
	infos := len(r.Metadata.InfoMessages)
	warns := len(r.Metadata.Warnings)

	content := fmt.Sprintf("Services: %d\nWarnings: %d\nInfo: %d\nFindings: %d",
		svcs, warns, infos, r.TotalFindings())

	return style.Render(content)
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
