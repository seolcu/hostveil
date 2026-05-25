package tui

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/bubbles/v2/table"
	"charm.land/lipgloss/v2"
	"github.com/seolcu/hostveil/internal/domain"
)

// ── Loading screen ──

func (m model) renderLoading() string {
	t := m.theme()
	if m.width < 40 || m.height < 10 {
		return lipgloss.NewStyle().
			Width(m.width).Height(m.height).
			Background(lipgloss.Color(t.Background)).
			Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
				lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Terminal too small")))
	}

	brand := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("hostveil")
	subtitle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(Version)
	heading := fmt.Sprintf("⟐  %s %s", brand, subtitle)

	spinnerView := m.spinner.View()

	toolOrder := []string{"update", "trivy", "lynis"}
	var toolLines []string
	totalWeight := 0
	doneWeight := 0
	for _, name := range toolOrder {
		ts, ok := m.snap.Tools[name]
		if !ok {
			continue
		}
		status := domain.ToolStatus(ts.Status)
		var icon string
		switch status {
		case domain.ToolPending:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("○")
			totalWeight++
		case domain.ToolRunning:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Render(spinnerView)
			totalWeight++
		case domain.ToolDone:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Success)).Bold(true).Render("✓")
			totalWeight++
			doneWeight++
		case domain.ToolSkipped:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("−")
			totalWeight++
			doneWeight++
		case domain.ToolError:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Critical)).Bold(true).Render("✗")
			totalWeight++
			doneWeight++
		default:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("○")
			totalWeight++
		}
		label := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(fmt.Sprintf("%-8s", name))
		toolLines = append(toolLines, fmt.Sprintf("  %s %s %s", icon, label, ts.Message))
	}

	pct := 0.0
	if totalWeight > 0 {
		pct = float64(doneWeight) / float64(totalWeight)
	}
	bar := renderProgressBar(pct, m.width-40)

	lines := []string{
		"",
		"  " + heading,
		"",
	}
	lines = append(lines, toolLines...)
	lines = append(lines,
		"",
		"  "+bar,
		"",
		"  "+lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("q quit"),
	)

	content := strings.Join(lines, "\n")
	return lipgloss.NewStyle().
		Width(m.width).Height(m.height).
		Background(lipgloss.Color(t.Background)).
		Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content))
}

// ── Main screen ──

func (m model) renderMain() string {
	t := m.theme()
	if m.width < 40 || m.height < 10 {
		return lipgloss.NewStyle().
			Width(m.width).Height(m.height).
			Background(lipgloss.Color(t.Background)).
			Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
				lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Terminal too small")))
	}

	header := m.renderHeader()
	sysinfo := m.renderSysInfo()
	metrics := m.renderMetrics()
	var body string
	if m.mode == paneDetail {
		body = m.renderDetailPane()
	} else {
		body = m.renderListPane()
	}
	sections := []string{header, sysinfo, metrics, body}
	return lipgloss.JoinVertical(lipgloss.Top, sections...)
}

// ── Header ──

func (m model) renderHeader() string {
	t := m.theme()
	brand := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("hostveil")
	ver := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(Version)
	tagline := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Linux self-hosting security scanner")

	left := fmt.Sprintf("%s %s", brand, ver)
	right := m.renderScorePlate()

	leftW := lipgloss.Width(left)
	rightW := lipgloss.Width(right)
	available := m.width - leftW - rightW - 4

	top := ""
	if available > lipgloss.Width(tagline)+2 {
		top = left + strings.Repeat(" ", available-lipgloss.Width(tagline)) + tagline + "  " + right
	} else if m.width-leftW-4 > 20 {
		top = left + strings.Repeat(" ", m.width-leftW-rightW-4) + right
	} else {
		top = lipgloss.JoinVertical(lipgloss.Left, left, right)
	}

	return lipgloss.NewStyle().
		Width(m.width).
		Padding(0, 1).
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Render(top)
}

func (m model) renderScorePlate() string {
	t := m.theme()
	score := m.snap.Score
	grade := m.snap.Grade

	scoreColor := scoreColor(score, t)
	scoreStr := lipgloss.NewStyle().
		Foreground(lipgloss.Color(scoreColor)).
		Bold(true).
		Render(fmt.Sprintf("%d/100", score))

	var lines []string
	lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("SCORE"))
	lines = append(lines, scoreStr)
	if grade != "" {
		lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Grade "+grade))
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(1, 2).
		Render(lipgloss.JoinVertical(lipgloss.Left, lines...))
}

func (m model) renderSysInfo() string {
	t := m.theme()
	host := m.snap.Hostname
	ip := m.snap.LocalIP
	if host == "" && ip == "" {
		return ""
	}
	label := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.TextMuted)).
		Render(fmt.Sprintf("%s @ %s", host, ip))
	return lipgloss.NewStyle().
		Width(m.width).
		Padding(0, 2).
		Render(label)
}

// ── Metrics bar ──

func (m model) renderMetrics() string {
	t := m.theme()
	findings := m.snap.Findings

	counts := map[domain.Severity]int{}
	sources := map[domain.Source]int{}
	fixable := 0
	for _, f := range findings {
		counts[f.Severity]++
		sources[f.Source]++
		if f.IsFixable() {
			fixable++
		}
	}

	type metric struct {
		label string
		value string
		color string
	}
	metrics := []metric{
		{"Total", fmt.Sprintf("%d", len(findings)), t.Text},
		{"Critical", fmt.Sprintf("%d", counts[domain.SeverityCritical]), t.Critical},
		{"High", fmt.Sprintf("%d", counts[domain.SeverityHigh]), t.High},
		{"Medium", fmt.Sprintf("%d", counts[domain.SeverityMedium]), t.Medium},
		{"Low", fmt.Sprintf("%d", counts[domain.SeverityLow]), t.Low},
		{"Fixable", fmt.Sprintf("%d", fixable), t.Accent},
	}

	cardW := max(14, (m.width-4)/len(metrics)-2)
	var cards []string
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
	for _, mt := range metrics {
		card := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(t.Border)).
			Width(cardW).
			Padding(0, 1).
			Render(
				muted.Render(mt.label) + "\n" +
					lipgloss.NewStyle().Foreground(lipgloss.Color(mt.color)).Bold(true).Render(mt.value),
			)
		cards = append(cards, card)
	}

	return lipgloss.NewStyle().Width(m.width).Padding(0, 1).Render(lipgloss.JoinHorizontal(lipgloss.Top, cards...))
}

// ── List pane ──

func (m model) renderListPane() string {
	t := m.theme()

	visible := m.visibleFindings()
	count := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(fmt.Sprintf("%d visible", len(visible)))

	filterInfo := fmt.Sprintf("[s:%s o:%s]", m.filter.source, m.filter.sortBy)
	if m.filter.severity != "all" {
		filterInfo += fmt.Sprintf(" sev:%s", m.filter.severity)
	}
	if m.filter.query != "" {
		filterInfo += fmt.Sprintf(" q:\"%s\"", m.filter.query)
	}

	filterLabel := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(filterInfo)

	headLeft := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Findings") + "  " + count
	headRight := filterLabel

	headW := m.listWidth()
	head := lipgloss.NewStyle().
		Width(headW).
		Padding(0, 1).
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Render(headLeft + strings.Repeat(" ", max(0, headW-lipgloss.Width(headLeft)-lipgloss.Width(headRight)-4)) + headRight)

	tableView := m.table.View()

	var footerEls []string
	footerEls = append(footerEls, m.help.ShortHelpView(m.listKeyMap().ShortHelp()))
	if m.toast != "" {
		toastStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.High)).Bold(true)
		footerEls = append(footerEls, toastStyle.Render(m.toast))
	}
	footerStyled := lipgloss.NewStyle().
		Width(headW).
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1).
		Render(lipgloss.JoinVertical(lipgloss.Top, footerEls...))

	return lipgloss.NewStyle().Width(headW).Render(
		lipgloss.JoinVertical(lipgloss.Top, head, tableView, footerStyled),
	)
}

func tableStyles(t Theme) table.Styles {
	s := table.DefaultStyles()
	s.Header = lipgloss.NewStyle().
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Foreground(lipgloss.Color(t.TextMuted)).
		Bold(true).
		Padding(0, 1)
	s.Cell = lipgloss.NewStyle().Padding(0, 1)
	s.Selected = lipgloss.NewStyle().
		Background(lipgloss.Color(t.Surface)).
		Foreground(lipgloss.Color(t.Accent)).
		Bold(true).
		Padding(0, 1)
	return s
}

// ── Detail pane ──

func (m model) renderDetailPane() string {
	t := m.theme()
	viewportStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1)

	detailContent := viewportStyle.Render(m.viewport.View())

	footer := m.help.ShortHelpView(m.detailKeyMap().ShortHelp())
	footerStyled := lipgloss.NewStyle().
		Width(m.detailWidth()).
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1).
		Render(footer)

	return lipgloss.NewStyle().Width(m.detailWidth()).Render(
		lipgloss.JoinVertical(lipgloss.Top, detailContent, footerStyled),
	)
}

// ── Detail content (used by viewport) ──

func renderDetailContent(t Theme, f *domain.Finding, width int) string {
	var b strings.Builder

	sevBadge := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(severityColor(f.Severity, t))).
		Foreground(lipgloss.Color(severityColor(f.Severity, t))).
		Bold(true).
		Padding(0, 1).
		Render(strings.ToUpper(f.Severity.String()))

	b.WriteString(sevBadge + " " + lipgloss.NewStyle().Bold(true).Render(f.Title))
	b.WriteString("\n\n")

	muted := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true)

	b.WriteString(muted.Render(fmt.Sprintf("%-12s", "ID")) + f.ID + "\n")
	b.WriteString(muted.Render(fmt.Sprintf("%-12s", "Source")) + f.Source.String() + "\n")
	b.WriteString(muted.Render(fmt.Sprintf("%-12s", "Remediation")) + f.Remediation.Label() + "\n")
	if f.Service != "" {
		b.WriteString(muted.Render(fmt.Sprintf("%-12s", "Service")) + f.Service + "\n")
	}

	if f.IsFixable() {
		b.WriteString("\n" + accent.Render("Press 'f' to fix") + "\n")
	}

	if f.Description != "" {
		b.WriteString("\n" + accent.Render("Description") + "\n")
		b.WriteString(lipgloss.Wrap(f.Description, width, " ") + "\n")
	}
	if f.HowToFix != "" {
		b.WriteString("\n" + accent.Render("How to fix") + "\n")
		b.WriteString(lipgloss.Wrap(f.HowToFix, width, " ") + "\n")
	}
	if len(f.Evidence) > 0 {
		b.WriteString("\n" + accent.Render("Evidence") + "\n")
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			prefix := muted.Render(fmt.Sprintf("  %-14s ", fit(k, 14)))
			b.WriteString(prefix + lipgloss.Wrap(f.Evidence[k], max(1, width-lipgloss.Width(prefix)), " ") + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// ── Modals ──

func (m model) renderWithModal(base string) string {
	var modal string
	switch m.modal {
	case modalHelp:
		modal = m.renderHelpModal()
	case modalTheme:
		modal = m.renderThemeModal()
	case modalFilter:
		modal = m.renderFilterModal()
	case modalFixConfirm:
		modal = m.renderFixConfirmModal()
	case modalFixResult:
		modal = m.renderFixResultModal()
	default:
		return base
	}

	mw, mh := lipgloss.Size(modal)
	x := max(0, (m.width-mw)/2)
	y := max(0, (m.height-mh)/2)
	return lipgloss.NewCompositor(
		lipgloss.NewLayer(base).X(0).Y(0).Z(0),
		lipgloss.NewLayer(modal).X(x).Y(y).Z(10),
	).Render()
}

func (m model) renderHelpModal() string {
	t := m.theme()
	s := m.modalStyle()

	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Help"),
		"",
	}
	if m.mode == paneList {
		lines = append(lines,
			lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("List mode"),
			"  j/↓, k/↑     Navigate findings",
			"  g/G          Top / bottom",
			"  Enter, l      Open detail",
			"  /             Search findings",
			"  t             Change theme",
			"  f             Apply fix",
			"  Ctrl+R        Recalculate score",
			"  0-4           Filter by severity (0=all, 1=critical...)",
			"  s             Cycle source filter (all→trivy→lynis)",
			"  o             Cycle sort order",
			"  R             Clear all filters",
			"  ?             This help",
			"  q             Quit",
		)
	} else {
		lines = append(lines,
			lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Detail mode"),
			"  j/↓, k/↑     Scroll detail",
			"  g/G          Top / bottom",
			"  Esc, h        Back to list",
			"  f             Apply fix",
			"  t             Change theme",
			"  Ctrl+R        Recalculate score",
			"  ?             This help",
			"  q             Quit",
		)
	}
	lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Press any key to close"))

	return s.Width(clamp(m.width-8, 48, 80)).Render(strings.Join(lines, "\n"))
}

func (m model) renderThemeModal() string {
	t := m.theme()
	s := m.modalStyle()
	themes := AllThemes()

	left := make([]string, 0, len(themes)+2)
	left = append(left,
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Theme"),
		"",
	)
	for i, th := range themes {
		mark := "  "
		nameStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text))
		if i == m.themeCursor {
			mark = "> "
			nameStyle = nameStyle.Foreground(lipgloss.Color(t.Accent)).Bold(true)
		}
		left = append(left, "  "+mark+nameStyle.Render(th.Name))
	}

	previewTheme := themes[clamp(m.themeCursor, 0, len(themes)-1)]
	preview := renderThemePreview(previewTheme)
	body := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(32).Render(strings.Join(left, "\n")),
		"  ",
		preview,
	)
	body += "\n\n" + lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("↑/↓ preview  Enter select  Esc cancel")
	return s.Width(clamp(m.width-8, 72, 110)).Render(body)
}

func (m model) renderFilterModal() string {
	t := m.theme()
	s := m.modalStyle()

	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Search findings"),
		"",
		m.searchBox.View(),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Press Enter to apply, Esc to cancel"),
	}
	return s.Width(clamp(m.width-8, 48, 76)).Render(strings.Join(lines, "\n"))
}

func (m model) renderFixConfirmModal() string {
	t := m.theme()
	s := m.modalStyle()

	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Apply fix"),
		"",
	}
	if m.fixTarget != nil && len(m.fixTarget.Actions) > 0 {
		lines = append(lines, lipgloss.NewStyle().Bold(true).Render(m.fixTarget.Label))

		action := m.fixTarget.Actions[m.fixActionIdx]
		if action.Warning != "" {
			lines = append(lines, "")
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.High)).Render("⚠ "+action.Warning))
		}

		if m.fixTarget.Class() == domain.RemediationReview {
			lines = append(lines, "")
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Actions:"))
			for i, a := range m.fixTarget.Actions {
				mark := "  "
				if i == m.fixActionIdx {
					mark = "> "
				}
				warn := ""
				if a.Warning != "" {
					warn = " ⚠"
				}
				lines = append(lines, fmt.Sprintf("  %s%s%s", mark, a.Label, warn))
			}
		}
	}
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Apply? (y/N)"))
	return s.Width(clamp(m.width-8, 48, 76)).Render(strings.Join(lines, "\n"))
}

func (m model) renderFixResultModal() string {
	t := m.theme()
	s := m.modalStyle()

	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Fix result"),
		"",
		m.fixResult,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Press any key to close"),
	}
	return s.Width(clamp(m.width-8, 48, 76)).Render(strings.Join(lines, "\n"))
}

func (m model) modalStyle() lipgloss.Style {
	t := m.theme()
	return lipgloss.NewStyle().
		Background(lipgloss.Color(t.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderBackground(lipgloss.Color(t.Surface)).
		Padding(1, 2)
}

func renderThemePreview(t Theme) string {
	s := lipgloss.NewStyle().
		Background(lipgloss.Color(t.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(1, 2).
		Width(44)

	rows := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Preview"),
		severityBadgeStr("HIGH", t.High) + "  " + severityBadgeStr("MED", t.Medium) + "  " + severityBadgeStr("LOW", t.Low),
		severityBadgeStr("CRIT", t.Critical) + "  sshd_config hardening",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Score 72/100  Grade B+"),
	}
	return s.Render(strings.Join(rows, "\n"))
}

func severityBadgeStr(label, color string) string {
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(color)).
		Foreground(lipgloss.Color(color)).
		Bold(true).
		Padding(0, 1).
		Render(label)
}

// ── Utility functions ──

func shortID(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return fit(id, 12)
}

func short(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

func fit(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	runes := []rune(s)
	for len(runes) > 0 && lipgloss.Width(string(runes)+"…") > width {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}

func clamp(v, low, high int) int {
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func renderProgressBar(pct float64, width int) string {
	if width < 10 {
		return ""
	}
	filled := int(pct * float64(width-2))
	if filled < 0 {
		filled = 0
	}
	if filled > width-2 {
		filled = width - 2
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-2-filled)
	pctStr := fmt.Sprintf(" %3.0f%% ", pct*100)
	return "[" + bar + "]" + pctStr
}

func severityColor(s domain.Severity, t Theme) string {
	switch s {
	case domain.SeverityCritical:
		return t.Critical
	case domain.SeverityHigh:
		return t.High
	case domain.SeverityMedium:
		return t.Medium
	case domain.SeverityLow:
		return t.Low
	default:
		return t.TextMuted
	}
}

func scoreColor(score uint8, t Theme) string {
	switch {
	case score >= 85:
		return t.Success
	case score >= 65:
		return t.Low
	case score >= 40:
		return t.Medium
	case score >= 20:
		return t.High
	default:
		return t.Critical
	}
}
