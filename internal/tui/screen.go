package tui

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/seolcu/hostveil/internal/domain"
)

// ── Loading screen ──

func (m model) renderLoading() string {
	t := m.theme()
	if m.width < 40 || m.height < 10 {
		return lipgloss.NewStyle().
			Width(m.width).Height(m.height).
			Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
				lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Terminal too small")))
	}

	brand := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("hostveil")
	subtitle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(Version)
	heading := fmt.Sprintf("%s %s", brand, subtitle)
	panelW := clamp(m.width-8, 56, 92)
	if m.width > 0 {
		panelW = min(panelW, m.width)
	}
	innerW := max(20, panelW-6)

	spinnerView := m.spinner.View()

	toolOrder := []string{"update", "trivy", "lynis", "compose"}
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
		case domain.ToolDegraded:
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color(t.High)).Bold(true).Render("◪")
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
		label := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(fmt.Sprintf("%-7s", name))
		message := fit(ts.Message, max(8, innerW-13))
		toolLines = append(toolLines, fmt.Sprintf("%s %s %s", icon, label, message))
	}

	pct := 0.0
	if totalWeight > 0 {
		pct = float64(doneWeight) / float64(totalWeight)
	}
	bar := renderProgressBar(pct, min(54, max(18, innerW-8)))

	lines := []string{
		heading,
		"",
	}
	lines = append(lines, toolLines...)
	lines = append(lines,
		"",
		bar,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("q quit"),
	)

	paintW := borderedPanelInnerWidth(panelW, 2)
	content := paintPanelBlock(t, paintW, strings.Join(lines, "\n"))
	panel := finalizeBorderedPanel(t, panelW, 0, 2, t.Border, content)
	return lipgloss.NewStyle().
		Width(m.width).Height(m.height).
		Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel))
}

// ── Main screen ──

func (m model) renderMain() string {
	t := m.theme()
	if m.width < 40 || m.height < 24 {
		return lipgloss.NewStyle().
			Width(m.width).Height(m.height).
			Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
				lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Terminal too small")))
	}

	header := m.renderHeader()
	metrics := m.renderMetrics()
	m.headerH = lipgloss.Height(header)
	m.metricsH = lipgloss.Height(metrics)
	body := m.renderContent()
	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Render(lipgloss.JoinVertical(lipgloss.Top, header, metrics, body))
}

func (m model) renderContent() string {
	fw := m.filterWidth()
	if fw > 0 {
		return lipgloss.JoinHorizontal(lipgloss.Top,
			m.renderFilterPanel(fw),
			strings.Repeat(" ", 2),
			m.renderListPane(),
			strings.Repeat(" ", 2),
			m.renderDetailPane(),
		)
	}

	if m.splitDetail() {
		return lipgloss.JoinHorizontal(lipgloss.Top,
			m.renderListPane(),
			strings.Repeat(" ", 2),
			m.renderDetailPane(),
		)
	}

	if m.mode == paneDetail {
		return m.renderDetailPane()
	}
	return m.renderListPane()
}

func (m model) filterWidth() int {
	if m.width < 190 {
		return 0
	}
	return 32
}

func (m model) renderFilterPanel(width int) string {
	t := m.theme()
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
	label := muted
	sectionLabel := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
	title := sectionLabel.Render("SEARCH FINDINGS")

	chip := func(text string, active bool) string {
		if active {
			return lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text)).Bold(true).Render("[" + text + "]")
		}
		return lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(text)
	}
	joinChips := func(values ...string) string {
		return strings.Join(values, " ")
	}

	searchValue := "> ssh, auth, cve, …"
	if m.filter.query != "" {
		searchValue = "> " + fit(m.filter.query, width-10-2)
	}
	searchBox := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.TextMuted)).
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderBackground(lipgloss.Color(t.SurfaceAlt)).
		Background(lipgloss.Color(t.SurfaceAlt)).
		Padding(0, 1).
		Width(width - 6).
		Render(searchValue)

	sev := joinChips(
		chip("All", m.filter.severity == "all"),
		chip("Critical", m.filter.severity == "critical"),
	)
	sev2 := joinChips(
		chip("High", m.filter.severity == "high"),
		chip("Medium", m.filter.severity == "medium"),
		chip("Low", m.filter.severity == "low"),
	)
	src := joinChips(
		chip("All", m.filter.source == "all"),
		chip("Lynis", m.filter.source == "lynis"),
		chip("Trivy", m.filter.source == "trivy"),
		chip("Compose", m.filter.source == "compose"),
	)
	rem := joinChips(
		chip("All", m.filter.remediation == "all"),
		chip("Auto", m.filter.remediation == "auto"),
		chip("Review", m.filter.remediation == "review"),
	)
	rem2 := joinChips(
		chip("Unavailable", m.filter.remediation == "unavailable"),
		chip("Manual", m.filter.remediation == "manual"),
	)
	sortDirIndicator := ""
	if m.filter.sortDir == "desc" {
		sortDirIndicator = " ↓"
	} else {
		sortDirIndicator = " ↑"
	}
	sortDisplay := map[string]string{
		"severity":    "Severity first",
		"source":      "Source",
		"title":       "Title",
		"remediation": "Remediation",
	}[m.filter.sortBy]
	if sortDisplay == "" {
		sortDisplay = m.filter.sortBy
	}
	sortDisplay += sortDirIndicator
	sortBox := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.Text)).
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderBackground(lipgloss.Color(t.SurfaceAlt)).
		Background(lipgloss.Color(t.SurfaceAlt)).
		Padding(0, 1).
		Width(width - 6).
		Render(sortDisplay)

	clear := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("R  Clear filters")
	lines := []string{
		title,
		searchBox,
		"",
		label.Render("SEVERITY"),
		sev,
		sev2,
		"",
		label.Render("SOURCE"),
		src,
		"",
		label.Render("REMEDIATION"),
		rem,
		rem2,
		"",
		label.Render("SORT"),
		sortBox,
		"",
		clear,
	}
	content := lipgloss.JoinVertical(lipgloss.Left, lines...)

	innerW := borderedPanelInnerWidth(width, 2)
	content = paintPanelBlock(t, innerW, content)

	return finalizeBorderedPanel(t, width, m.bodyHeight(), 2, t.Border, content)
}

func finalizeBorderedPanel(t Theme, outerWidth, height, hPad int, borderColor string, content string) string {
	painted := content
	if hPad > 0 {
		painted = lipgloss.NewStyle().
			Padding(1, hPad).
			Background(lipgloss.Color(t.SurfaceAlt)).
			Render(painted)
	}
	rendered := borderedPanelStyle(t, outerWidth, height, borderColor).Render(painted)
	return reanchorPanelBG(rendered, panelBGSequence(t.SurfaceAlt, t.Text))
}

// ── Header ──

func (m model) renderHeader() string {
	t := m.theme()
	eyebrow := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.Accent)).
		Render("FINDS AND FIXES SECURITY ISSUES")
	brand := m.renderBrand()
	lines := []string{eyebrow}
	lines = append(lines, brand)
	if sys := m.sysInfoLine(); sys != "" {
		sysStyled := lipgloss.NewStyle().
			Foreground(lipgloss.Color(t.Text)).
			Bold(true).
			Render(sys)
		lines = append(lines, sysStyled)
	}
	left := strings.Join(lines, "\n")
	right := m.renderScorePlate()

	innerW := max(1, m.width-4)
	if m.width < 86 {
		return lipgloss.NewStyle().
			Width(m.width).
			Padding(1, 2).
			Render(lipgloss.JoinVertical(lipgloss.Left, left, "", right))
	}

	rightW := lipgloss.Width(right)
	gap := 3
	leftW := max(24, innerW-rightW-gap)
	body := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(leftW).Render(left),
		strings.Repeat(" ", gap),
		right,
	)

	return lipgloss.NewStyle().
		Width(m.width).
		Padding(1, 2).
		Render(body)
}

func (m model) renderBrand() string {
	t := m.theme()
	if m.width < 100 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color(t.Text)).
			Bold(true).
			Render("hostveil")
	}
	logo := strings.Join([]string{
		" _               _             _ _",
		"| |__   ___  ___| |___   _____(_) |",
		"| '_ \\ / _ \\/ __| __\\ \\ / / _ \\ | |",
		"| | | | (_) \\__ \\ |_ \\ V /  __/ | |",
		"|_| |_|\\___/|___/\\__| \\_/ \\___|_|_|",
	}, "\n")
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.Text)).
		Bold(true).
		Render(logo)
}

func (m model) renderScorePlate() string {
	t := m.theme()
	score := m.snap.Score

	var scoreStr string
	if len(m.snap.Findings) == 0 {
		scoreStr = lipgloss.NewStyle().
			Foreground(lipgloss.Color(t.Success)).
			Bold(true).
			Render("Clean")
	} else {
		scoreColor := scoreColor(score, t)
		scoreStr = lipgloss.NewStyle().
			Foreground(lipgloss.Color(scoreColor)).
			Bold(true).
			Render(fmt.Sprintf("%d/100", score))
	}

	label := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.TextMuted)).
		Render("SECURITY SCORE")

	lines := []string{label, scoreStr}
	if axes := m.snap.ScoreBreakdown.Axes; len(axes) > 0 {
		lines = append(lines, "")
		for _, axis := range axes {
			axisLabel := fit(axis.Label, 14)
			penalty := axis.Penalty
			if penalty > axis.MaxPenalty {
				penalty = axis.MaxPenalty
			}
			meta := fmt.Sprintf("%d/%d", penalty, axis.MaxPenalty)
			scoreStyled := lipgloss.NewStyle().
				Foreground(lipgloss.Color(scoreColor(uint8(axis.Score), t))).
				Bold(true).
				Render(fmt.Sprintf("%3d", axis.Score))
			line := fmt.Sprintf("%s %s  %s",
				lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(axisLabel),
				scoreStyled,
				lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(meta),
			)
			lines = append(lines, line)
		}
	}

	// Match the brand area's height so the card stretches to align with the
	// sysinfo line (mirrors the Web UI's `align-items: stretch` on `.topbar`).
	height := max(6, m.brandHeight())
	if len(lines) > 2 {
		height = max(height, len(lines)+2)
	}

	innerW := borderedPanelInnerWidth(28, 2)
	plateBody := paintPanelBlock(t, innerW, lipgloss.JoinVertical(lipgloss.Left, lines...))

	return finalizeBorderedPanel(t, 28, height, 2, t.Border, plateBody)
}

// brandHeight returns the number of text lines the brand area occupies:
// eyebrow + ASCII logo (or wordmark) + optional sysinfo. The score plate
// stretches to match.
func (m model) brandHeight() int {
	h := 1 // eyebrow
	if m.width >= 100 {
		h += 5 // 5-line ASCII logo
	} else {
		h += 1 // single-line wordmark
	}
	if m.sysInfoLine() != "" {
		h++
	}
	return h
}

func (m model) sysInfoLine() string {
	host := m.snap.Hostname
	ip := m.snap.LocalIP
	if host == "" && ip == "" {
		return ""
	}
	if host == "" {
		return ip
	}
	if ip == "" {
		return host
	}
	return fmt.Sprintf("%s @ %s", host, ip)
}

// ── Metrics bar ──

func (m model) renderMetrics() string {
	t := m.theme()
	findings := m.snap.Findings

	counts := map[domain.Severity]int{}
	fixable := 0
	for _, f := range findings {
		counts[f.Severity]++
		if f.IsFixable() {
			fixable++
		}
	}

	type metric struct {
		label string
		value string
		color string
		big   bool
	}
	metrics := []metric{
		{"TOTAL", fmt.Sprintf("%d", len(findings)), t.Accent, true},
		{"CRITICAL", fmt.Sprintf("%d", counts[domain.SeverityCritical]), t.Critical, false},
		{"HIGH", fmt.Sprintf("%d", counts[domain.SeverityHigh]), t.High, false},
		{"MEDIUM", fmt.Sprintf("%d", counts[domain.SeverityMedium]), t.Medium, false},
		{"LOW", fmt.Sprintf("%d", counts[domain.SeverityLow]), t.Low, false},
		{"FIXABLE", fmt.Sprintf("%d", fixable), t.Accent, false},
	}

	cols := len(metrics)
	if m.width < 70 {
		cols = 2
	} else if m.width < 118 {
		cols = 3
	}
	cardW := max(13, (m.width-4-(cols-1))/cols)
	var cards []string
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
	for _, mt := range metrics {
		borderColor := t.Border
		if mt.big {
			borderColor = t.Accent
		}
		valueStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(mt.color)).
			Bold(true)
		innerW := borderedPanelInnerWidth(cardW, 2)
		cardBody := paintPanelBlock(t, innerW,
			muted.Render(mt.label)+"\n"+valueStyle.Render(mt.value),
		)
		card := finalizeBorderedPanel(t, cardW, 0, 2, borderColor, cardBody)
		cards = append(cards, card)
	}

	rows := make([]string, 0, (len(cards)+cols-1)/cols)
	for i := 0; i < len(cards); i += cols {
		end := min(i+cols, len(cards))
		rowParts := make([]string, 0, cols*2-1)
		for j := i; j < end; j++ {
			if j > i {
				rowParts = append(rowParts, " ")
			}
			rowParts = append(rowParts, cards[j])
		}
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, rowParts...))
	}

	return lipgloss.NewStyle().Width(m.width).Padding(0, 2).Render(lipgloss.JoinVertical(lipgloss.Top, rows...))
}

// ── List pane ──

func (m model) renderListPane() string {
	t := m.theme()

	visible := m.visibleFindings()
	count := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text)).Bold(true).Render(fmt.Sprintf("%d visible", len(visible)))

	filterInfo := fmt.Sprintf("s:%s o:%s(%s)", m.filter.source, m.filter.sortBy, m.filter.sortDir)
	if m.filter.severity != "all" {
		filterInfo += fmt.Sprintf("  sev:%s", m.filter.severity)
	}
	if m.filter.remediation != "all" {
		filterInfo += fmt.Sprintf("  rem:%s", m.filter.remediation)
	}
	if m.filter.service != "all" {
		filterInfo += fmt.Sprintf("  svc:%s", fit(m.filter.service, 16))
	}
	if m.filter.query != "" {
		filterInfo += fmt.Sprintf("  q:%q", fit(m.filter.query, 16))
	}

	titleColor := t.Accent
	if m.mode != paneList {
		titleColor = t.TextMuted
	}

	headLeft := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.NewStyle().Foreground(lipgloss.Color(titleColor)).Render("FINDINGS"),
		count,
	)
	headW := m.listWidth()
	headRightW := max(1, headW-lipgloss.Width(headLeft)-7)
	headRight := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(fit(filterInfo, headRightW))
	head := lipgloss.NewStyle().
		Width(panelContentWidth(headW)).
		Padding(1, 1).
		Background(lipgloss.Color(t.SurfaceAlt)).
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderBottomForeground(lipgloss.Color(t.Border)).
		Render(lipgloss.JoinHorizontal(lipgloss.Top,
			headLeft,
			strings.Repeat(" ", max(1, headW-lipgloss.Width(headLeft)-lipgloss.Width(headRight)-4)),
			headRight,
		))

	tbl := m.table
	tableH := m.listHeight()
	if visLen := len(visible); visLen+1 < tableH {
		tableH = visLen + 1
	}
	tbl.SetHeight(tableH)
	tableView := m.paintTableView(t, tbl.View(), panelContentWidth(headW))

	var footerEls []string
	footerEls = append(footerEls, m.footerHelp(paneList, max(1, headW-4)))
	selectedVisible := 0
	for _, f := range visible {
		if m.selectedSet[f.ID] && isBatchFixableFinding(f) {
			selectedVisible++
		}
	}
	if selectedVisible > 0 {
		selLabel := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render(fmt.Sprintf("%d selected — press f to batch fix", selectedVisible))
		footerEls = append(footerEls, selLabel)
	}
	if m.toast != "" {
		toastStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true)
		footerEls = append(footerEls, toastStyle.Render(m.toast))
	}
	footerStyled := lipgloss.NewStyle().
		Width(panelContentWidth(headW)).
		Background(lipgloss.Color(t.SurfaceAlt)).
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderTopForeground(lipgloss.Color(t.Border)).
		Padding(0, 2).
		Render(lipgloss.JoinVertical(lipgloss.Top, footerEls...))

	borderColor := t.Border
	if m.mode == paneList {
		borderColor = t.Accent
	}

	top := lipgloss.JoinVertical(lipgloss.Top,
		paintPanelBlock(t, panelContentWidth(headW), head),
		tableView,
	)
	panelInnerW := panelContentWidth(headW)
	footerStyled = paintPanelBlock(t, panelInnerW, footerStyled)
	panelInnerH := m.bodyHeight() - 2 // minus border
	emptyLines := panelInnerH - lipgloss.Height(top) - lipgloss.Height(footerStyled)
	if emptyLines < 0 {
		emptyLines = 0
	}
	body := joinPanelSections(t, panelInnerW, top, footerStyled, emptyLines)

	return finalizeBorderedPanel(t, headW, m.bodyHeight(), 0, borderColor, body)
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
		Foreground(lipgloss.Color(t.Text)).
		Bold(true)
	return s
}

// paintTableView fills each table row to the panel width with a solid background.
func (m model) paintTableView(t Theme, tableView string, width int) string {
	if tableView == "" {
		return panelGapLine(t, width)
	}
	lines := strings.Split(tableView, "\n")
	cursor := m.table.Cursor()
	for i, line := range lines {
		bg := t.SurfaceAlt
		if i > 0 && i-1 == cursor {
			bg = selectionBackground(t)
		}
		lines[i] = paintPanelLineBG(t, width, line, bg)
	}
	return strings.Join(lines, "\n")
}

func (m model) footerHelp(mode paneMode, width int) string {
	t := m.theme()
	text := "j/k navigate · space select · enter detail · / search · v service · f fix · ? help · q quit"
	if mode == paneDetail {
		text = "j/k scroll · esc list · tab focus · f fix · ? help · q quit"
	}
	if width < 72 {
		if mode == paneDetail {
			text = "j/k · esc · f fix · tab · ? · q"
		} else {
			text = "j/k nav · space select · enter · v · ? · q"
		}
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(fit(text, width))
}

// ── Detail pane ──

func (m model) renderDetailPane() string {
	t := m.theme()
	innerW := max(1, m.detailWidth()-4)
	vp := m.viewport

	// Reserve rows at the bottom for the footer so the keyboard hints
	// anchor to the very bottom of the panel and the content hugs the
	// top — instead of leaving a big blank gap between the description
	// and the hints.
	footerReserved := 3 // border-top + 1 content + 1 padding
	vpH := max(4, m.detailHeight()-footerReserved)
	vp.SetHeight(vpH)
	contentW := max(1, panelContentWidth(m.detailWidth())-4)
	detailContent := lipgloss.NewStyle().
		Padding(1, 2).
		Background(lipgloss.Color(t.SurfaceAlt)).
		Render(paintPanelBlock(t, contentW, vp.View()))

	footer := m.footerHelp(paneDetail, innerW)
	var footerEls []string
	footerEls = append(footerEls, footer)
	if m.toast != "" {
		toastStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true)
		footerEls = append(footerEls, toastStyle.Render(m.toast))
	}
	footerStyled := lipgloss.NewStyle().
		Width(innerW).
		Background(lipgloss.Color(t.SurfaceAlt)).
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderTopForeground(lipgloss.Color(t.Border)).
		Padding(0, 2).
		Render(lipgloss.JoinVertical(lipgloss.Top, footerEls...))

	borderColor := t.Border
	if m.mode == paneDetail {
		borderColor = t.Accent
	}

	// Manually push the footer to the bottom by inserting blank lines
	// between the content and the footer block. AlignVertical/Bottom
	// is not enough on its own because it would also push the content
	// down — we want content-at-top + footer-at-bottom.
	panelInnerW := panelContentWidth(m.detailWidth())
	detailContent = paintPanelBlock(t, panelInnerW, detailContent)
	footerStyled = paintPanelBlock(t, panelInnerW, footerStyled)
	panelInnerH := m.bodyHeight() - 2 // minus border
	emptyLines := panelInnerH - lipgloss.Height(detailContent) - lipgloss.Height(footerStyled)
	if emptyLines < 0 {
		emptyLines = 0
	}
	body := joinPanelSections(t, panelInnerW, detailContent, footerStyled, emptyLines)

	return finalizeBorderedPanel(t, m.detailWidth(), m.bodyHeight(), 0, borderColor, body)
}

// ── Detail content (used by viewport) ──

func renderDetailContent(t Theme, f *domain.Finding, width int) string {
	var b strings.Builder

	muted := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true)
	text := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text))

	sevBadge := severityBadgeStr(strings.ToUpper(f.Severity.String()), severityColor(f.Severity, t))
	b.WriteString(sevBadge + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text)).Bold(true).Render(lipgloss.Wrap(detailTitle(*f), width, " ")))
	b.WriteString("\n")

	metaContentW := max(1, width-6)
	metaValueW := max(1, metaContentW-12)
	metaRow := func(label, value string) string {
		prefix := muted.Render(fmt.Sprintf("%-12s", label))
		lines := strings.Split(lipgloss.Wrap(value, metaValueW, " "), "\n")
		for i, line := range lines {
			if i == 0 {
				lines[i] = prefix + text.Render(line)
			} else {
				lines[i] = strings.Repeat(" ", 12) + text.Render(line)
			}
		}
		return strings.Join(lines, "\n")
	}
	metaRows := []string{
		metaRow("ID", f.ID),
		metaRow("Source", f.Source.String()),
		metaRow("Remediation", remediationShortLabel(f.Remediation)+" — "+remediationHint(f.Remediation)),
	}
	if f.Service != "" {
		metaRows = append(metaRows, metaRow("Service", f.Service))
	}
	meta := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderBackground(lipgloss.Color(t.SurfaceAlt)).
		Background(lipgloss.Color(t.SurfaceAlt)).
		Padding(1, 2).
		Width(width).
		Render(strings.Join(metaRows, "\n"))
	b.WriteString("\n" + meta + "\n")

	writeSection := func(title, body string) {
		if body == "" {
			return
		}
		b.WriteString("\n" + accent.Render(strings.ToUpper(title)) + "\n")
		b.WriteString(text.Render(lipgloss.Wrap(body, width, " ")) + "\n")
	}

	writeSection("Description", f.Description)
	writeSection("How to fix", f.HowToFix)
	if len(f.Evidence) > 0 {
		b.WriteString("\n" + accent.Render(fmt.Sprintf("EVIDENCE (%d)", len(f.Evidence))) + "\n")
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			blockInnerW := max(1, width-4)
			block := lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color(t.Border)).
				BorderBackground(lipgloss.Color(t.SurfaceAlt)).
				Background(lipgloss.Color(t.SurfaceAlt)).
				Padding(0, 1).
				Width(width).
				Render(muted.Render(fit(k, blockInnerW)) + "\n" + text.Render(lipgloss.Wrap(f.Evidence[k], blockInnerW, " ")))
			b.WriteString(block + "\n")
		}
	}
	if len(f.Metadata) > 0 {
		b.WriteString("\n" + accent.Render(fmt.Sprintf("METADATA (%d)", len(f.Metadata))) + "\n")
		keys := make([]string, 0, len(f.Metadata))
		for k := range f.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			blockInnerW := max(1, width-4)
			block := lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color(t.Border)).
				BorderBackground(lipgloss.Color(t.SurfaceAlt)).
				Background(lipgloss.Color(t.SurfaceAlt)).
				Padding(0, 1).
				Width(width).
				Render(muted.Render(fit(k, blockInnerW)) + "\n" + text.Render(lipgloss.Wrap(f.Metadata[k], blockInnerW, " ")))
			b.WriteString(block + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// ── Modals ──

func (m model) renderWithModal(base string) string {
	if m.width < 40 || m.height < 10 {
		return base
	}
	var modal string
	switch m.modal {
	case modalHelp:
		modal = m.renderHelpModal()
	case modalFilter:
		modal = m.renderFilterModal()
	case modalDryRun:
		modal = m.renderFixDryRunModal()
	case modalFixConfirm:
		modal = m.renderFixConfirmModal()
	case modalFixResult:
		modal = m.renderFixResultModal()
	case modalFixProgress:
		modal = m.renderFixProgressModal()
	case modalExport:
		modal = m.renderExportModal()
	case modalTheme:
		modal = m.renderThemeModal()
	default:
		return base
	}

	mw, mh := lipgloss.Size(modal)
	x := max(0, (m.width-mw)/2)
	y := max(0, (m.height-mh)/2)
	dimmed := lipgloss.NewStyle().Faint(true).Render(base)
	return lipgloss.NewCompositor(
		lipgloss.NewLayer(dimmed).X(0).Y(0).Z(0),
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
			"  f             Apply fix",
			"  Space         Select for batch fix",
			"  Ctrl+A        Select/deselect all visible",
			"  Ctrl+R        Recalculate score",
			"  Ctrl+S        Rescan all tools",
			"  0-4           Filter by severity (0=all, 1=critical...)",
			"  s             Cycle source filter (all→trivy→lynis→compose)",
			"  r             Cycle remediation filter",
			"                (all→auto→review→unavailable→manual)",
			"  o             Cycle sort order",
			"  O             Toggle sort direction",
			"  R             Clear all filters",
			"  e             Export report (JSON/CSV/AI)",
			"  t             Color scheme",
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
			"  e             Export report (JSON/CSV/AI)",
			"  Ctrl+R        Recalculate score",
			"  Ctrl+S        Rescan all tools",
			"  Ctrl+A        Select/deselect all visible",
			"  ?             This help",
			"  t             Color scheme",
			"  q             Quit",
		)
	}
	lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Press q, esc, ? or enter to close"))

	return s.Width(m.modalWidth(80)).Render(strings.Join(lines, "\n"))
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
	return s.Width(m.modalWidth(76)).Render(strings.Join(lines, "\n"))
}

func (m model) renderFixDryRunModal() string {
	t := m.theme()
	s := m.modalStyle()

	label := m.fixTarget.Label
	multi := len(m.dryRunActions) > 1
	title := "Apply fix"
	if multi {
		title = "Choose action"
	}
	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render(title),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text)).Bold(true).Render(label),
		"",
	}

	for i, info := range m.dryRunActions {
		prefix := "  "
		if multi && i == m.dryRunApplyIdx {
			prefix = "> "
		}
		typeTag := " [" + info.actionType + "]"
		warn := ""
		if info.warning != "" {
			warn = " ⚠"
		}
		actionLine := fmt.Sprintf("%s%s%s%s", prefix, info.label, typeTag, warn)
		if !multi || i == m.dryRunApplyIdx {
			style := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text))
			if multi && i == m.dryRunApplyIdx {
				style = style.Foreground(lipgloss.Color(t.Accent)).Bold(true)
			}
			lines = append(lines, style.Render(actionLine))
		} else {
			lines = append(lines, actionLine)
		}

		if i == m.dryRunApplyIdx && info.warning != "" {
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.High)).Render("  ⚠ "+info.warning))
		}
		if i == m.dryRunApplyIdx && info.diffPreview != "" {
			diffLines := strings.Split(info.diffPreview, "\n")
			diffStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
			lines = append(lines, "")
			lines = append(lines, diffStyle.Render("  Diff preview:"))
			for _, dl := range diffLines {
				lines = append(lines, diffStyle.Render("  "+dl))
			}
		}
	}

	if multi {
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("↑/↓ select · Enter confirm · Esc cancel"))
	} else {
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Enter apply · Esc cancel"))
	}

	return s.Width(m.modalWidth(80)).Render(strings.Join(lines, "\n"))
}

func (m model) renderFixConfirmModal() string {
	t := m.theme()
	s := m.modalStyle()

	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Apply fix"),
		"",
	}
	if m.fixTarget != nil && len(m.fixTarget.Actions) > 0 {
		lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text)).Bold(true).Render(m.fixTarget.Label))

		// Clamp the action index so a stale value (e.g. left over from a
		// previous multi-action fix) cannot index past the end.
		idx := m.fixActionIdx
		if idx < 0 || idx >= len(m.fixTarget.Actions) {
			idx = 0
		}
		action := m.fixTarget.Actions[idx]
		if action.Warning != "" {
			lines = append(lines, "")
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.High)).Render("⚠ "+action.Warning))
		}

		if m.fixTarget.Class() == domain.RemediationReview {
			lines = append(lines, "")
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Actions:"))
			for i, a := range m.fixTarget.Actions {
				mark := "  "
				style := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text))
				if i == idx {
					mark = "> "
					style = style.Foreground(lipgloss.Color(t.Accent)).Bold(true)
				}
				warn := ""
				if a.Warning != "" {
					warn = " ⚠"
				}
				lines = append(lines, style.Render(fmt.Sprintf("%s%s%s", mark, a.Label, warn)))
			}
		}
	}
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Apply? (y/N)"))
	return s.Width(m.modalWidth(76)).Render(strings.Join(lines, "\n"))
}

func (m model) renderFixResultModal() string {
	t := m.theme()
	s := m.modalStyle()

	resultBody := m.fixResult
	if strings.HasPrefix(m.fixResult, "✓") {
		resultBody = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Success)).Render(m.fixResult)
	} else if strings.HasPrefix(m.fixResult, "✗") {
		resultBody = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Critical)).Render(m.fixResult)
	} else if strings.Contains(m.fixResult, "\n\n") {
		parts := strings.SplitN(m.fixResult, "\n\n", 2)
		head := parts[0]
		diff := parts[1]
		headStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Success))
		if strings.HasPrefix(head, "✗") {
			headStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(t.Critical))
		}
		diffStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
		resultBody = headStyle.Render(head) + "\n\n" + diffStyle.Render(diff)
	}

	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Fix result"),
		"",
		resultBody,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Press any key to close"),
	}
	return s.Width(m.modalWidth(76)).Render(strings.Join(lines, "\n"))
}

func (m model) renderFixProgressModal() string {
	t := m.theme()
	s := m.modalStyle()

	pct := 0
	if m.fixProgressTotal > 0 {
		pct = m.fixProgress * 100 / m.fixProgressTotal
	}
	modalW := m.modalWidth(64)
	barW := min(30, max(10, modalContentWidth(modalW)-6))
	bar := renderProgressBar(float64(pct)/100.0, barW)
	if bar == "" {
		bar = strings.Repeat("░", barW)
	}

	title := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Applying fixes")
	header := fmt.Sprintf("%d / %d", m.fixProgress, m.fixProgressTotal)

	barLine := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Render(bar)

	var labelLine string
	if m.fixProgressLabel != "" {
		labelLine = lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("  " + m.fixProgressLabel)
	}

	lines := []string{
		title,
		"",
		header,
		barLine,
	}
	if labelLine != "" {
		lines = append(lines, labelLine)
	}

	return s.Width(modalW).Render(strings.Join(lines, "\n"))
}

func (m model) renderExportModal() string {
	t := m.theme()
	s := m.modalStyle()

	var items []string
	for i, f := range exportFormats {
		items = append(items, renderSelectableItem(t, f.label, i == m.exportIdx))
	}

	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Export report"),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Choose format:"),
		"",
	}
	lines = append(lines, items...)
	lines = append(lines,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("↑/↓ select · Enter export · Esc cancel"),
	)
	return s.Width(m.modalWidth(64)).Render(strings.Join(lines, "\n"))
}

func (m model) renderThemeModal() string {
	t := m.theme()
	s := m.modalStyle()

	var items []string
	for i, id := range ThemeIDs() {
		label := ThemeLabel(id)
		if id == m.themeName {
			label += " (current)"
		}
		items = append(items, renderSelectableItem(t, label, i == m.themeIdx))
	}

	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Color scheme"),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Choose palette:"),
		"",
	}
	lines = append(lines, items...)
	lines = append(lines,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("↑/↓ select · Enter apply · Esc cancel"),
	)
	return s.Width(m.modalWidth(64)).Render(strings.Join(lines, "\n"))
}

func (m model) modalStyle() lipgloss.Style {
	t := m.theme()
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		BorderBackground(lipgloss.Color(t.SurfaceAlt)).
		Background(lipgloss.Color(t.SurfaceAlt)).
		Padding(1, 2)
}

func (m model) modalWidth(maxWidth int) int {
	width := clamp(m.width-8, 48, maxWidth)
	if m.width > 0 {
		width = min(width, m.width)
	}
	return max(1, width)
}

func modalContentWidth(width int) int {
	return max(1, width-6)
}

func joinPanelSections(t Theme, width int, top, bottom string, gap int) string {
	if gap < 0 {
		gap = 0
	}
	parts := []string{top}
	for range gap {
		parts = append(parts, panelGapLine(t, width))
	}
	parts = append(parts, bottom)
	return strings.Join(parts, "\n")
}

// borderedPanelInnerWidth returns drawable width inside a bordered panel with horizontal padding.
func borderedPanelInnerWidth(outerWidth, horizontalPadding int) int {
	return max(1, outerWidth-2-2*horizontalPadding)
}

// panelContentWidth returns the drawable inner width inside a bordered panel.
func panelContentWidth(outer int) int {
	return max(1, outer-2)
}

// selectionBackground returns a row highlight color distinct from SurfaceAlt.
func selectionBackground(t Theme) string {
	return t.Border
}

// borderedPanelStyle returns a bordered box style with a solid panel fill.
func borderedPanelStyle(t Theme, outerWidth, height int, borderColor string) lipgloss.Style {
	s := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(borderColor)).
		Background(lipgloss.Color(t.SurfaceAlt)).
		BorderBackground(lipgloss.Color(t.SurfaceAlt)).
		Width(outerWidth)
	if height > 0 {
		s = s.Height(height)
	}
	return s
}

// panelBGSequence returns an ANSI prefix that sets panel foreground and background.
func panelBGSequence(bg, fg string) string {
	rendered := lipgloss.NewStyle().
		Foreground(lipgloss.Color(fg)).
		Background(lipgloss.Color(bg)).
		Render(" ")
	if idx := strings.IndexByte(rendered, ' '); idx > 0 {
		return rendered[:idx]
	}
	return rendered
}

// reanchorPanelBG replaces style resets so panel background survives nested styles.
func reanchorPanelBG(s, bgSeq string) string {
	s = strings.ReplaceAll(s, "\x1b[0m", bgSeq)
	s = strings.ReplaceAll(s, "\x1b[m", bgSeq)
	return s
}

// paintPanelLineBG renders one line with a full-width solid background.
func paintPanelLineBG(t Theme, width int, line, bg string) string {
	if width <= 0 {
		return line
	}
	if strings.TrimSpace(stripANSI(line)) == "" && lipgloss.Width(line) == 0 {
		return lipgloss.NewStyle().
			Width(width).
			Background(lipgloss.Color(bg)).
			Render(strings.Repeat(" ", width))
	}
	bgSeq := panelBGSequence(bg, t.Text)
	line = reanchorPanelBG(line, bgSeq)
	if pad := width - lipgloss.Width(line); pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	rendered := lipgloss.NewStyle().
		Width(width).
		Foreground(lipgloss.Color(t.Text)).
		Background(lipgloss.Color(bg)).
		Render(line)
	return reanchorPanelBG(rendered, bgSeq)
}

// stripANSI removes ANSI escape sequences for empty-line detection.
func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	esc := false
	for i := 0; i < len(s); i++ {
		if esc {
			if s[i] == 'm' {
				esc = false
			}
			continue
		}
		if s[i] == '\x1b' {
			esc = true
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// paintPanelLine renders one line with the default panel background fill.
func paintPanelLine(t Theme, width int, line string) string {
	return paintPanelLineBG(t, width, line, t.SurfaceAlt)
}

// paintPanelBlock paints every line in a block to the same full width.
func paintPanelBlock(t Theme, width int, block string) string {
	if block == "" {
		return panelGapLine(t, width)
	}
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		lines[i] = paintPanelLine(t, width, line)
	}
	return strings.Join(lines, "\n")
}

// panelGapLine renders a blank panel row with a solid background fill.
func panelGapLine(t Theme, width int) string {
	return paintPanelLine(t, width, "")
}

func joinVerticalWithGap(top, bottom string, gap int) string {
	if gap < 0 {
		gap = 0
	}
	return top + strings.Repeat("\n", gap+1) + bottom
}

func severityBadgeStr(label, color string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(color)).
		Bold(true).
		Render("[" + label + "]")
}

// inputStyles returns themed textinput styles for the search modal.
func inputStyles(t Theme) textinput.Styles {
	state := textinput.StyleState{
		Text:        lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text)),
		Placeholder: lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)),
		Suggestion:  lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)),
		Prompt:      lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)),
	}
	return textinput.Styles{
		Focused: state,
		Blurred: state,
		Cursor: textinput.CursorStyle{
			Color: lipgloss.Color(t.Accent),
			Shape: tea.CursorBlock,
			Blink: true,
		},
	}
}

// styledTableSeverity returns a color-coded severity cell for the findings table.
func styledTableSeverity(t Theme, f domain.Finding) string {
	if f.Fixed {
		return lipgloss.NewStyle().Foreground(lipgloss.Color(t.Success)).Bold(true).Render("✓")
	}
	sev := strings.ToUpper(f.Severity.String())
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(severityColor(f.Severity, t))).
		Bold(true).
		Render(fit(sev, 8))
}

// styledTableTitle returns a table title cell, dimming and striking through fixed findings.
func styledTableTitle(t Theme, f domain.Finding, maxWidth int) string {
	title := findingTitle(f)
	if f.Fixed {
		title = lipgloss.NewStyle().
			Foreground(lipgloss.Color(t.TextMuted)).
			Strikethrough(true).
			Render(title)
	}
	return fit(title, maxWidth)
}

// renderSelectableItem renders one highlighted option row for export/theme modals.
func renderSelectableItem(t Theme, label string, selected bool) string {
	mark := "  "
	style := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text))
	if selected {
		mark = "> "
		style = style.Foreground(lipgloss.Color(t.Accent)).Bold(true)
	}
	return mark + style.Render(label)
}

// ── Utility functions ──

func findingTitle(f domain.Finding) string {
	if strings.TrimSpace(f.Title) != "" {
		return strings.TrimSpace(f.Title)
	}
	if strings.TrimSpace(f.Description) != "" {
		desc := strings.TrimSpace(f.Description)
		if idx := strings.Index(desc, ". "); idx > 0 {
			return strings.TrimSpace(desc[:idx+1])
		}
		return desc
	}
	if strings.TrimSpace(f.ID) != "" {
		return f.ID
	}
	return "Untitled finding"
}

func detailTitle(f domain.Finding) string {
	title := findingTitle(f)
	if strings.Contains(title, "...") || strings.Contains(title, "…") {
		if desc := firstSentence(f.Description); desc != "" {
			return desc
		}
	}
	return title
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if idx := strings.Index(s, ". "); idx > 0 {
		return strings.TrimSpace(s[:idx+1])
	}
	return s
}

func shortID(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return fit(id, 12)
}

func remediationShortLabel(r domain.RemediationKind) string {
	switch r {
	case domain.RemediationAuto:
		return "Auto"
	case domain.RemediationReview:
		return "Review"
	case domain.RemediationUnavailable:
		return "Unavailable"
	case domain.RemediationManual:
		return "Manual"
	default:
		return "Unknown"
	}
}

// remediationHint returns a short, user-facing explanation of what a
// RemediationKind means in practice. Shown next to the bare kind name
// in the detail panel, since "Auto"/"Review"/"Manual"/"Unavailable" are
// not self-explanatory to a first-time user.
func remediationHint(r domain.RemediationKind) string {
	switch r {
	case domain.RemediationAuto:
		return "one clear fix, click Apply"
	case domain.RemediationReview:
		return "multiple options, pick one"
	case domain.RemediationUnavailable:
		return "not yet classified"
	case domain.RemediationManual:
		return "no automated fix, see guidance below"
	default:
		return ""
	}
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
