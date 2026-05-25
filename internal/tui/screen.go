package tui

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/seolcu/hostveil/internal/domain"
)

type layout struct {
	width, height int
	headerH       int
	summaryH      int
	footerH       int
	bodyH         int
	listW         int
	detailW       int
	listH         int
	twoPane       bool
	compact       bool
}

type styles struct {
	app      lipgloss.Style
	header   lipgloss.Style
	summary  lipgloss.Style
	panel    lipgloss.Style
	footer   lipgloss.Style
	row      lipgloss.Style
	selected lipgloss.Style
	modal    lipgloss.Style
	muted    lipgloss.Style
	accent   lipgloss.Style
}

func computeLayout(width, height int, detail bool) layout {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}

	l := layout{width: width, height: height, headerH: 2, summaryH: 3, footerH: 2}
	l.compact = width < 90 || height < 22
	if l.compact {
		l.summaryH = 2
	}
	l.bodyH = height - l.headerH - l.summaryH - l.footerH
	if l.bodyH < 3 {
		l.bodyH = 3
	}
	l.twoPane = detail && width >= 100
	if l.twoPane {
		l.listW = width / 2
		l.detailW = width - l.listW - 1
	} else {
		l.listW = width
		l.detailW = width
	}
	l.listH = l.bodyH
	return l
}

func makeStyles(t Theme, l layout) styles {
	return styles{
		app: lipgloss.NewStyle().
			Width(l.width).Height(l.height).
			Background(lipgloss.Color(t.Background)).ColorWhitespace(true),
		header: lipgloss.NewStyle().
			Width(max(0, l.width-2)).
			Background(lipgloss.Color(t.Surface)).ColorWhitespace(true).
			BorderBottom(true).BorderForeground(lipgloss.Color(t.Border)).
			Padding(0, 1),
		summary: lipgloss.NewStyle().
			Width(max(0, l.width-2)).
			Background(lipgloss.Color(t.Background)).ColorWhitespace(true).
			BorderBottom(true).BorderForeground(lipgloss.Color(t.Border)).
			Padding(0, 1),
		panel: lipgloss.NewStyle().
			Background(lipgloss.Color(t.Background)).ColorWhitespace(true),
		footer: lipgloss.NewStyle().
			Width(max(0, l.width-2)).
			Background(lipgloss.Color(t.Surface)).ColorWhitespace(true).
			BorderTop(true).BorderForeground(lipgloss.Color(t.Border)).
			Padding(0, 1),
		row: lipgloss.NewStyle().
			Background(lipgloss.Color(t.Background)).ColorWhitespace(true).
			Foreground(lipgloss.Color(t.Text)),
		selected: lipgloss.NewStyle().
			Background(lipgloss.Color(t.Surface)).ColorWhitespace(true).
			Foreground(lipgloss.Color(t.Accent)).Bold(true),
		modal: lipgloss.NewStyle().
			Background(lipgloss.Color(t.Surface)).ColorWhitespace(true).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(t.Border)).
			BorderBackground(lipgloss.Color(t.Surface)).
			Padding(1, 2),
		muted:  lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)),
		accent: lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true),
	}
}

func renderLoading(m model) string {
	t := m.theme()
	l := computeLayout(m.width, m.height, false)
	s := makeStyles(t, l)
	spinner := string([]rune("⠋⠙⠹⠸")[m.tickCount%4])

	if l.width < 50 || l.height < 12 {
		return s.app.Render(lipgloss.Place(l.width, l.height, lipgloss.Center, lipgloss.Center,
			s.muted.Render("Terminal too small for hostveil")))
	}

	brand := s.accent.Render("hostveil") + " " + s.muted.Render(Version)
	heading := fmt.Sprintf("%s  %s", s.muted.Render("⟐"), brand)
	phase := s.muted.Render("Scanning...")

	toolOrder := []string{"update", "trivy", "lynis"}
	var toolLines []string
	for _, name := range toolOrder {
		tRaw, ok := m.snap.Tools[name]
		if !ok {
			continue
		}
		status := domain.ToolStatus(tRaw.Status)
		icon := s.muted.Render(string(spinner))
		switch status {
		case domain.ToolPending:
			icon = s.muted.Render("○")
		case domain.ToolRunning:
			icon = s.accent.Render(string(spinner))
		case domain.ToolDone:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Success)).Bold(true).Render("✓")
		case domain.ToolSkipped:
			icon = s.muted.Render("−")
		case domain.ToolError:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Critical)).Bold(true).Render("✗")
		default:
			icon = s.muted.Render("○")
		}
		label := s.muted.Render(fmt.Sprintf("%-8s", name))
		toolLines = append(toolLines, fmt.Sprintf("  %s %s %s", icon, label, tRaw.Message))
	}

	lines := []string{
		"",
		"  " + heading,
		"",
		"  " + phase,
	}
	lines = append(lines, toolLines...)
	lines = append(lines,
		"",
		"  "+s.muted.Render("q quit"),
	)

	content := strings.Join(lines, "\n")
	return s.app.Render(lipgloss.Place(l.width, l.height, lipgloss.Center, lipgloss.Center, content))
}

func renderBase(m model) string {
	t := m.theme()
	l := computeLayout(m.width, m.height, m.mode == modeDetail)
	s := makeStyles(t, l)

	if l.width < 50 || l.height < 12 {
		return s.app.Render(lipgloss.Place(l.width, l.height, lipgloss.Center, lipgloss.Center,
			s.muted.Render("Terminal too small for hostveil")))
	}

	header := renderHeader(t, s, l)
	summary := renderSummary(t, s, l, m.snap.Findings, m.snap.Score, m.snap.Grade)
	body := renderBody(t, s, l, m)
	footer := s.footer.Render(m.help.ShortHelpView(keyBindings(m).ShortHelp()))

	return s.app.Render(lipgloss.JoinVertical(lipgloss.Top, header, summary, body, footer))
}

func renderHeader(t Theme, s styles, l layout) string {
	brand := s.accent.Render("hostveil") + " " + s.muted.Render(Version)
	right := s.muted.Render("Linux self-hosting security scanner")
	space := l.width - 2 - lipgloss.Width(brand) - lipgloss.Width(right)
	if space < 1 {
		return s.header.Render(fit(brand, l.width-2))
	}
	return s.header.Render(brand + strings.Repeat(" ", space) + right)
}

func renderSummary(t Theme, s styles, l layout, findings []domain.Finding, score uint8, grade string) string {
	counts := severityCounts(findings)
	fixable := 0
	sources := map[domain.Source]int{}
	for _, f := range findings {
		if f.IsFixable() {
			fixable++
		}
		sources[f.Source]++
	}

	scoreStr := lipgloss.NewStyle().Foreground(lipgloss.Color(scoreColor(score, t))).Bold(true).Render(fmt.Sprintf("Score %d/100", score))
	if grade != "" {
		scoreStr += " " + s.muted.Render("Grade "+grade)
	}
	line1 := strings.Join([]string{
		scoreStr,
		fmt.Sprintf("Findings %d", len(findings)),
		colorText(fmt.Sprintf("Critical %d", counts[domain.SeverityCritical]), t.Critical),
		colorText(fmt.Sprintf("High %d", counts[domain.SeverityHigh]), t.High),
		colorText(fmt.Sprintf("Medium %d", counts[domain.SeverityMedium]), t.Medium),
		colorText(fmt.Sprintf("Low %d", counts[domain.SeverityLow]), t.Low),
	}, "  ")

	if l.compact {
		return s.summary.Render(fit(line1, l.width-2))
	}

	line2 := s.muted.Render(fmt.Sprintf("Trivy %d  Lynis %d  Fixable %d", sources[domain.SourceTrivy], sources[domain.SourceLynis], fixable))
	return s.summary.Render(fit(line1, l.width-2) + "\n" + fit(line2, l.width-2))
}

func renderBody(t Theme, s styles, l layout, m model) string {
	list := renderFindings(t, s, l.listW, l.listH, m.snap.Findings, m.selected, m.listOffset)
	if m.mode != modeDetail || len(m.snap.Findings) == 0 {
		return list
	}

	detail := renderDetail(t, l.detailW, l.bodyH, &m.snap.Findings[m.selected], m.detailOffset)
	if !l.twoPane {
		return detail
	}

	gutter := lipgloss.NewStyle().Width(1).Height(l.bodyH).Background(lipgloss.Color(t.Background)).ColorWhitespace(true).Render("")
	return lipgloss.JoinHorizontal(lipgloss.Top, list, gutter, detail)
}

func renderFindings(t Theme, s styles, width, height int, findings []domain.Finding, selected, offset int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	if len(findings) == 0 {
		return s.panel.Width(width).Height(height).Align(lipgloss.Center).Foreground(lipgloss.Color(t.TextMuted)).Render("No findings")
	}

	end := min(len(findings), offset+height)
	rows := make([]string, 0, height)
	for i := offset; i < end; i++ {
		rows = append(rows, renderFindingRow(t, s, width, findings[i], i == selected))
	}
	for len(rows) < height {
		rows = append(rows, s.row.Width(width).Render(""))
	}
	return s.panel.Width(width).Height(height).Render(strings.Join(rows, "\n"))
}

func renderFindingRow(t Theme, s styles, width int, f domain.Finding, selected bool) string {
	bg := t.Background
	style := s.row.Width(width).MaxWidth(width).Inline(true)
	cursor := " "
	if selected {
		bg = t.Surface
		style = s.selected.Width(width).MaxWidth(width).Inline(true)
		cursor = ">"
	}

	sev := token(strings.ToUpper(short(f.Severity.String(), 3)), severityColor(f.Severity, t), bg)
	src := token(strings.ToUpper(short(f.Source.String(), 3)), t.TextMuted, bg)
	rem := token(f.Remediation.Label(), t.TextMuted, bg)
	id := shortID(f.ID)
	prefixPlain := fmt.Sprintf("%s %-3s %-3s %-12s ", cursor, strings.ToUpper(short(f.Severity.String(), 3)), strings.ToUpper(short(f.Source.String(), 3)), id)
	prefix := fmt.Sprintf("%s %s %s %-12s ", cursor, sev, src, id)
	reserved := lipgloss.Width(prefixPlain) + lipgloss.Width(f.Remediation.Label()) + 2
	title := fit(f.Title, max(0, width-reserved))
	line := prefix + title + "  " + rem
	line += lipgloss.NewStyle().Background(lipgloss.Color(bg)).Render(strings.Repeat(" ", max(0, width-lipgloss.Width(line))))
	return style.Render(line)
}

func renderDetail(t Theme, width, height int, f *domain.Finding, offset int) string {
	inner := max(1, width-4)
	content := scrollLines(renderDetailContent(t, f, inner), max(1, height-2), offset)
	return lipgloss.NewStyle().
		Width(inner).
		Height(max(1, height-2)).
		Background(lipgloss.Color(t.Surface)).
		ColorWhitespace(true).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderBackground(lipgloss.Color(t.Surface)).
		Padding(0, 1).
		Render(content)
}

func renderDetailContent(t Theme, f *domain.Finding, width int) string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(severityColor(f.Severity, t))).Bold(true).Render(lipgloss.Wrap(f.Title, width, " ")))
	b.WriteString("\n\n")
	b.WriteString(metaLine(t, "Severity", strings.ToUpper(f.Severity.String())))
	b.WriteString(metaLine(t, "Source", f.Source.String()))
	b.WriteString(metaLine(t, "ID", f.ID))
	if f.Service != "" {
		b.WriteString(metaLine(t, "Service", f.Service))
	}
	b.WriteString(metaLine(t, "Remediation", f.Remediation.Label()))

	if f.IsFixable() {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Press 'f' to fix") + "\n")
	}

	if f.Description != "" {
		b.WriteString("\n" + sectionTitle(t, "Description") + "\n")
		b.WriteString(lipgloss.Wrap(f.Description, width, " ") + "\n")
	}
	if f.HowToFix != "" {
		b.WriteString("\n" + sectionTitle(t, "How to fix") + "\n")
		b.WriteString(lipgloss.Wrap(f.HowToFix, width, " ") + "\n")
	}
	if len(f.Evidence) > 0 {
		b.WriteString("\n" + sectionTitle(t, "Evidence") + "\n")
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			prefix := fmt.Sprintf("  %-14s ", fit(k, 14))
			b.WriteString(prefix + lipgloss.Wrap(f.Evidence[k], max(1, width-lipgloss.Width(prefix)), " ") + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func renderWithModal(m model, base string) string {
	t := m.theme()
	l := computeLayout(m.width, m.height, m.mode == modeDetail)
	s := makeStyles(t, l)

	var modal string
	switch m.modal {
	case modalHelp:
		modal = renderHelpModal(t, s, l)
	case modalTheme:
		modal = renderThemeModal(t, s, l, m.themeCursor)
	case modalFixConfirm:
		modal = renderFixConfirmModal(t, s, l, m)
	case modalFixResult:
		modal = renderFixResultModal(t, s, l, m)
	default:
		return base
	}

	mw, mh := lipgloss.Size(modal)
	x := max(0, (l.width-mw)/2)
	y := max(0, (l.height-mh)/2)
	return lipgloss.NewCompositor(
		lipgloss.NewLayer(base).X(0).Y(0).Z(0),
		lipgloss.NewLayer(modal).X(x).Y(y).Z(10),
	).Render()
}

func renderHelpModal(t Theme, s styles, l layout) string {
	lines := []string{
		s.accent.Render("Help"),
		"",
		s.muted.Render("Navigation"),
		"  ↑/k, ↓/j        Move selection or scroll details",
		"  Enter, l, →      Open selected finding",
		"  Esc, q           Back or close modal",
		"",
		s.muted.Render("Actions"),
		"  ?                Show this help",
		"  s                Theme settings",
		"  q                Quit from the main list",
		"  Ctrl+C           Quit immediately",
	}
	return s.modal.Width(clamp(l.width-8, 48, 76)).Render(strings.Join(lines, "\n"))
}

func renderThemeModal(t Theme, s styles, l layout, cursor int) string {
	themes := AllThemes()
	left := make([]string, 0, len(themes)+2)
	left = append(left, s.accent.Render("Theme"), "")
	for i, th := range themes {
		mark := "  "
		nameStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text))
		if i == cursor {
			mark = "> "
			nameStyle = nameStyle.Foreground(lipgloss.Color(t.Accent)).Bold(true)
		}
		left = append(left, "  "+mark+nameStyle.Render(th.Name))
	}

	previewTheme := themes[clamp(cursor, 0, len(themes)-1)]
	preview := renderThemePreview(previewTheme)
	body := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(30).Render(strings.Join(left, "\n")),
		lipgloss.NewStyle().Width(2).Render(""),
		preview,
	)
	body += "\n\n" + s.muted.Render("↑/k preview  ↓/j preview  Enter select  Esc/q cancel")
	return s.modal.Width(clamp(l.width-8, 72, 108)).Render(body)
}

func renderFixConfirmModal(t Theme, s styles, l layout, m model) string {
	lines := []string{
		s.accent.Render("Apply fix"),
		"",
	}
	if m.fixTarget != nil && len(m.fixTarget.Actions) > 0 {
		lines = append(lines, s.header.Render(m.fixTarget.Label))

		action := m.fixTarget.Actions[m.fixActionIdx]
		if action.Warning != "" {
			lines = append(lines, "")
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.High)).Render("⚠ "+action.Warning))
		}

		if m.fixTarget.Class() == domain.RemediationReview {
			lines = append(lines, "")
			lines = append(lines, s.muted.Render("Actions:"))
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
	lines = append(lines, s.muted.Render("Apply? (y/N)"))
	return s.modal.Width(clamp(l.width-8, 48, 76)).Render(strings.Join(lines, "\n"))
}

func renderFixResultModal(t Theme, s styles, l layout, m model) string {
	lines := []string{
		s.accent.Render("Fix result"),
		"",
		m.fixResult,
		"",
		s.muted.Render("Press enter to close"),
	}
	return s.modal.Width(clamp(l.width-8, 48, 76)).Render(strings.Join(lines, "\n"))
}

func renderThemePreview(t Theme) string {
	l := computeLayout(44, 10, false)
	s := makeStyles(t, l)
	rows := []string{
		s.accent.Render("Preview"),
		colorText("Score 72/100", scoreColor(72, t)) + "  Findings 12",
		token("MED", t.Medium, t.Surface) + "  " + token("LYN", t.TextMuted, t.Surface) + "  SSH hardening recommendation",
		token("HIG", t.High, t.Surface) + "  " + token("TRI", t.TextMuted, t.Surface) + "  Container image vulnerability",
	}
	return s.modal.Width(42).Render(strings.Join(rows, "\n"))
}

func colorText(s, color string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true).Render(s)
}

func token(s, fg, bg string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color(fg)).Background(lipgloss.Color(bg)).Bold(true).Render(s)
}

func sectionTitle(t Theme, title string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render(title)
}

func metaLine(t Theme, key, value string) string {
	label := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(fmt.Sprintf("%-12s", key))
	return label + value + "\n"
}

func scrollLines(content string, height, offset int) string {
	lines := strings.Split(content, "\n")
	if offset > len(lines)-height {
		offset = len(lines) - height
	}
	if offset < 0 {
		offset = 0
	}
	end := min(len(lines), offset+height)
	visible := append([]string{}, lines[offset:end]...)
	for len(visible) < height {
		visible = append(visible, "")
	}
	return strings.Join(visible, "\n")
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

func severityCounts(findings []domain.Finding) map[domain.Severity]int {
	counts := map[domain.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
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

func shortID(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) > 1 {
		id = parts[len(parts)-1]
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
