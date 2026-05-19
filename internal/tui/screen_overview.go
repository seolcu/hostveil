package tui

import (
	"fmt"
	"sort"
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

func remediationLabel(r domain.RemediationKind) string {
	switch r {
	case domain.RemediationAuto:
		return "Auto-fix"
	case domain.RemediationReview:
		return "Review"
	default:
		return "Manual"
	}
}

func remediationColor(r domain.RemediationKind, theme Theme) string {
	switch r {
	case domain.RemediationAuto:
		return theme.Success
	case domain.RemediationReview:
		return theme.Accent
	default:
		return theme.TextMuted
	}
}

func (m *overviewModel) render(r *domain.ScanResult, theme Theme, width, height int) string {
	if width < 20 {
		return "Terminal too narrow"
	}

	if width < miniWidth {
		return m.renderMiniDashboard(r, theme, width)
	}

	summary := m.renderSummaryLine(r, theme, width)

	switch {
	case width >= wideWidth:
		col3 := (width - 6) / 3
		col2 := (width - 2) / 2
		full := width - 2

		nextActions := m.renderNextActionsCard(r, theme, col3)
		riskByArea := m.renderRiskByAreaCard(r, theme, col3)
		affectedSvcs := m.renderAffectedServicesCard(r, theme, col3)
		fixQueue := m.renderFixQueueCard(r, theme, col2)
		scanCtx := m.renderScanContextCard(r, theme, col2)
		rec := m.renderRecommendationCard(r, theme, full)

		top := lipgloss.JoinHorizontal(lipgloss.Top, nextActions, "  ", riskByArea, "  ", affectedSvcs)
		middle := lipgloss.JoinHorizontal(lipgloss.Top, fixQueue, "  ", scanCtx)

		body := lipgloss.JoinVertical(lipgloss.Top, top, "", middle, "", rec)
		return summary + "\n" + body

	case width >= mediumWidth:
		col2 := (width - 2) / 2
		full := width - 2

		nextActions := m.renderNextActionsCard(r, theme, col2)
		riskByArea := m.renderRiskByAreaCard(r, theme, col2)
		affectedSvcs := m.renderAffectedServicesCard(r, theme, col2)
		hostCard := m.renderHostCard(r, theme, col2)
		fixQueue := m.renderFixQueueCard(r, theme, col2)
		scanCtx := m.renderScanContextCard(r, theme, col2)
		rec := m.renderRecommendationCard(r, theme, full)

		left := lipgloss.JoinVertical(lipgloss.Top, nextActions, affectedSvcs)
		right := lipgloss.JoinVertical(lipgloss.Top, riskByArea, hostCard)
		topRow := lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
		bottomRow := lipgloss.JoinHorizontal(lipgloss.Top, fixQueue, "  ", scanCtx)

		body := lipgloss.JoinVertical(lipgloss.Top, topRow, "", bottomRow, "", rec)
		return summary + "\n" + body

	default:
		colWidth := width - 2
		nextActions := m.renderNextActionsCard(r, theme, colWidth)
		riskByArea := m.renderRiskByAreaCard(r, theme, colWidth)
		affectedSvcs := m.renderAffectedServicesCard(r, theme, colWidth)
		hostCard := m.renderHostCard(r, theme, colWidth)
		fixQueue := m.renderFixQueueCard(r, theme, colWidth)
		scanCtx := m.renderScanContextCard(r, theme, colWidth)
		rec := m.renderRecommendationCard(r, theme, colWidth)
		body := lipgloss.JoinVertical(lipgloss.Top, nextActions, riskByArea, affectedSvcs, hostCard, fixQueue, scanCtx, rec)
		return summary + "\n" + body
	}
}

func (m *overviewModel) renderMiniDashboard(r *domain.ScanResult, theme Theme, width int) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	findings := r.TotalFindings()
	svcCount := len(r.Metadata.Services)

	gradeColor := theme.Critical
	if score >= 50 {
		gradeColor = theme.Medium
	}
	if score >= 80 {
		gradeColor = theme.Success
	}

	line1 := lipgloss.NewStyle().Bold(true).Render("hostveil")
	line2 := lipgloss.JoinHorizontal(lipgloss.Center,
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score %d/%d", score, 100)),
		" · ",
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(grade),
	)
	line3 := fmt.Sprintf("%d findings · %d %s", findings, svcCount, pluralize("service", svcCount))
	line4 := "Press 2 findings · ? help · q quit"

	style := lipgloss.NewStyle().Width(width).Padding(0, 1)
	return style.Render(line1 + "\n" + line2 + "\n" + line3 + "\n" + line4)
}

func (m *overviewModel) renderSummaryLine(r *domain.ScanResult, theme Theme, width int) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	findings := r.TotalFindings()
	svcCount := len(r.Metadata.Services)

	autoCount := 0
	for _, f := range r.Findings {
		if f.Remediation == domain.RemediationAuto {
			autoCount++
		}
	}

	gradeColor := theme.Critical
	if score >= 50 {
		gradeColor = theme.Medium
	}
	if score >= 80 {
		gradeColor = theme.Success
	}

	scoreStr := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score: %d/100", score))
	riskStr := lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Risk: %s", grade))

	parts := []string{
		scoreStr,
		riskStr,
		fmt.Sprintf("%d findings", findings),
		fmt.Sprintf("%d %s", svcCount, pluralize("service", svcCount)),
	}

	if autoCount > 0 {
		parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Success)).Render(fmt.Sprintf("%d auto-fixable", autoCount)))
	}

	line := strings.Join(parts, "  ·  ")

	style := lipgloss.NewStyle().
		Width(width).
		Padding(0, 1)

	return style.Render(line)
}

func pluralize(s string, n int) string {
	if n == 1 {
		return s
	}
	return s + "s"
}

func (m *overviewModel) renderNextActionsCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Next actions")
	var rows []string

	// Sort findings: severity order (Critical > High > Medium > Low), then remediation (Auto > Review > Manual)
	sorted := make([]domain.Finding, len(r.Findings))
	copy(sorted, r.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity < sorted[j].Severity
		}
		return sorted[i].Remediation < sorted[j].Remediation
	})

	maxActions := 3
	if width < 60 {
		maxActions = 2
	}

	count := 0
	for _, f := range sorted {
		if count >= maxActions {
			break
		}
		sevColor := f.Severity.Color()
		icon := severityIcon(f.Severity)
		sevLabel := strings.ToUpper(f.Severity.String()[:4])
		sevTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(sevColor)).
			Render(fmt.Sprintf("%s %s", icon, sevLabel))

		remLabel := remediationLabel(f.Remediation)
		remColor := remediationColor(f.Remediation, theme)
		remTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(remColor)).
			Render(remLabel)

		svc := f.Service
		if svc == "" {
			svc = "-"
		}
		svcTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(svc)

		titleLine := f.Title
		maxTitle := width - len(sevLabel) - len(svc) - 12
		if maxTitle < 20 {
			maxTitle = 20
		}
		titleLine = truncateStr(titleLine, maxTitle)

		rows = append(rows, fmt.Sprintf("  %s  %s  %s  %s", sevTag, svcTag, titleLine, remTag))
		count++
	}

	if len(rows) == 0 {
		rows = append(rows, "  No findings to act on")
	}

	return style.Render(title + "\n" + strings.Join(rows, "\n"))
}

func (m *overviewModel) renderRiskByAreaCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Risk by area")
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
		barWidth = barWidth * 3 / 5

		labelText := axis.Label()
		if width < 35 {
			switch labelText {
			case "Excessive Permissions":
				labelText = "Permissions"
			case "Unnecessary Exposure":
				labelText = "Exposure"
			case "Update & Supply Chain":
				labelText = "Supply Chain"
			case "Sensitive Data":
				labelText = "Sensitive"
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

	return style.Render(title + "\n" + lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderAffectedServicesCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Affected services")
	var rows []string

	// Group by service
	type svcInfo struct {
		name        string
		findings    int
		fixable     int
	}
	svcMap := make(map[string]*svcInfo)
	var svcOrder []string
	for _, f := range r.Findings {
		svc := f.Service
		if svc == "" {
			svc = "(project)"
		}
		if _, ok := svcMap[svc]; !ok {
			svcMap[svc] = &svcInfo{name: svc}
			svcOrder = append(svcOrder, svc)
		}
		svcMap[svc].findings++
		if f.IsFixable() {
			svcMap[svc].fixable++
		}
	}

	for _, name := range svcOrder {
		info := svcMap[name]
		svcLabel := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.Accent)).
			Render(name)

		countStr := fmt.Sprintf("%d findings", info.findings)
		if info.fixable > 0 {
			countStr += fmt.Sprintf("  (%d fixable)", info.fixable)
		}
		countLabel := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(countStr)

		spacer := width - lipgloss.Width(svcLabel) - lipgloss.Width(countStr) - 8
		if spacer < 1 {
			spacer = 1
		}

		rows = append(rows, fmt.Sprintf("  %s%s%s", svcLabel, strings.Repeat(" ", spacer), countLabel))
	}

	if len(rows) == 0 {
		rows = append(rows, "  No services affected")
	}

	return style.Render(title + "\n" + strings.Join(rows, "\n"))
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

func (m *overviewModel) renderFixQueueCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Fix queue")
	var rows []string

	autoCount := 0
	reviewCount := 0
	manualCount := 0
	var firstFixable *domain.Finding
	for _, f := range r.Findings {
		switch f.Remediation {
		case domain.RemediationAuto:
			autoCount++
			if firstFixable == nil {
				firstFixable = &f
			}
		case domain.RemediationReview:
			reviewCount++
			if firstFixable == nil {
				firstFixable = &f
			}
		case domain.RemediationManual:
			manualCount++
		}
	}

	total := autoCount + reviewCount + manualCount
	if total == 0 {
		rows = append(rows, "  No fixable findings")
	} else {
		var parts []string
		if autoCount > 0 {
			parts = append(parts, fmt.Sprintf("%d auto", autoCount))
		}
		if reviewCount > 0 {
			parts = append(parts, fmt.Sprintf("%d review", reviewCount))
		}
		if manualCount > 0 {
			parts = append(parts, fmt.Sprintf("%d manual", manualCount))
		}
		rows = append(rows, fmt.Sprintf("  %s can be previewed", strings.Join(parts, "  ·  ")))

		if firstFixable != nil {
			rows = append(rows, "  Press 2 → p to preview the first fix")
		}
	}

	return style.Render(title + "\n" + strings.Join(rows, "\n"))
}

func (m *overviewModel) renderScanContextCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Scan context")
	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("%-12s %s", k+":", v))
	}

	// Host info
	info := r.Metadata.HostRuntime
	if info != nil {
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
	}

	// Scan context
	if len(r.Metadata.Services) > 0 {
		if len(r.Metadata.Services) == 1 {
			addRow("Service", r.Metadata.Services[0].Name)
		} else {
			names := make([]string, len(r.Metadata.Services))
			for i, s := range r.Metadata.Services {
				names[i] = s.Name
			}
			addRow("Services", fmt.Sprintf("%d (%s)", len(r.Metadata.Services), strings.Join(names, ", ")))
		}
	}
	if r.Metadata.ComposeFile != "" {
		addRow("Compose", r.Metadata.ComposeFile)
	}
	if len(r.Metadata.Adapters) > 0 {
		names := make([]string, len(r.Metadata.Adapters))
		for i, a := range r.Metadata.Adapters {
			names[i] = a.Name
		}
		addRow("Adapters", strings.Join(names, ", "))
	}

	if len(rows) == 0 {
		rows = append(rows, "  No scan context available")
	}

	return style.Render(title + "\n" + lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderRecommendationCard(r *domain.ScanResult, theme Theme, width int) string {
	if len(r.Findings) == 0 {
		return ""
	}

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Recommendation")
	var desc string

	lowestScore := uint8(100)
	lowestAxis := ""
	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		if score < lowestScore {
			lowestScore = score
			lowestAxis = axis.Label()
		}
	}

	grade := r.ScoreReport.Grade()
	if lowestScore >= 80 {
		desc = "Overall security posture is Good. Maintain current practices."
	} else {
		desc = fmt.Sprintf("Overall risk is %s because %s score is %d.",
			grade, strings.ToLower(lowestAxis), lowestScore)

		lowLabel := strings.ToLower(lowestAxis)
		switch {
		case strings.Contains(lowLabel, "exposure"):
			desc += " Start with public bindings and reverse proxy configuration first."
		case strings.Contains(lowLabel, "sensitive"):
			desc += " Review secrets management, env variables, and data volume permissions."
		case strings.Contains(lowLabel, "permission"):
			desc += " Audit file permissions, drop capabilities, and restrict privilege escalation."
		case strings.Contains(lowLabel, "supply"):
			desc += " Pin image versions and enable automatic security updates."
		case strings.Contains(lowLabel, "host"):
			desc += " Harden the host: SSH config, firewall rules, kernel parameters, and defenses."
		}
	}

	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	return style.Render(title + "\n" + desc)
}
