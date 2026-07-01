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
			Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
				lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Terminal too small")))
	}

	brand := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("hostveil")
	subtitle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(Version)
	heading := fmt.Sprintf("%s %s", brand, subtitle)
	panelW := clamp(m.width-8, 56, 92)
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

	content := lipgloss.NewStyle().Width(innerW).Render(strings.Join(lines, "\n"))
	panel := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(1, 2).
		Width(panelW).
		Render(content)
	return lipgloss.NewStyle().
		Width(m.width).Height(m.height).
		Render(lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel))
}

// ── Main screen ──

func (m model) renderMain() string {
	t := m.theme()
	if m.width < 40 || m.height < 10 {
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

	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Width(width).
		Padding(1, 2).
		Render(content)
}

// ── Header ──

func (m model) renderHeader() string {
	t := m.theme()
	eyebrow := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.Accent)).
		Render("LINUX SELF-HOSTING SECURITY SCANNER")
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

	// Match the brand area's height so the card stretches to align with the
	// sysinfo line (mirrors the Web UI's `align-items: stretch` on `.topbar`).
	height := max(6, m.brandHeight())

	// When the card is stretched to 7+ lines, center the content vertically
	// so the extra space distributes above and below instead of leaving an
	// empty row at the bottom.
	vPad := 1
	if height > 6 {
		vPad = 2
	}

	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(vPad, 2).
		Width(24).
		Height(height).
		Render(lipgloss.JoinVertical(lipgloss.Left, label, scoreStr))
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
	cardW := max(13, (m.width-4-(cols-1))/cols-1)
	var cards []string
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted))
	for _, mt := range metrics {
		border := lipgloss.NormalBorder()
		borderColor := t.Border
		if mt.big {
			borderColor = t.Accent
		}
		valueStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(mt.color)).
			Bold(true)
		card := lipgloss.NewStyle().
			Border(border).
			BorderForeground(lipgloss.Color(borderColor)).
			Width(cardW).
			Padding(1, 2).
			Render(
				muted.Render(mt.label) + "\n" +
					valueStyle.Render(mt.value),
			)
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
		filterInfo += fmt.Sprintf("  svc:%s", m.filter.service)
	}
	if m.filter.query != "" {
		filterInfo += fmt.Sprintf("  q:%q", m.filter.query)
	}

	filterLabel := lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render(filterInfo)

	titleColor := t.Accent
	if m.mode != paneList {
		titleColor = t.TextMuted
	}

	headLeft := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.NewStyle().Foreground(lipgloss.Color(titleColor)).Render("FINDINGS"),
		count,
	)
	headRight := filterLabel

	headW := m.listWidth()
	head := lipgloss.NewStyle().
		Width(headW).
		Padding(1, 2).
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Render(lipgloss.JoinHorizontal(lipgloss.Top,
			headLeft,
			strings.Repeat(" ", max(1, headW-lipgloss.Width(headLeft)-lipgloss.Width(headRight)-6)),
			headRight,
		))

	tbl := m.table
	tableH := m.listHeight()
	if visible := m.visibleFindings(); len(visible)+1 < tableH {
		tableH = len(visible) + 1
	}
	tbl.SetHeight(tableH)
	tableView := tbl.View()

	var footerEls []string
	footerEls = append(footerEls, m.footerHelp(paneList, max(1, headW-4)))
	if len(m.selectedSet) > 0 {
		selLabel := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render(fmt.Sprintf("%d selected — press f to batch fix", len(m.selectedSet)))
		footerEls = append(footerEls, selLabel)
	}
	if m.toast != "" {
		toastStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true)
		footerEls = append(footerEls, toastStyle.Render(m.toast))
	}
	footerStyled := lipgloss.NewStyle().
		Width(headW).
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 2).
		Render(lipgloss.JoinVertical(lipgloss.Top, footerEls...))

	borderColor := t.Border
	if m.mode == paneList {
		borderColor = t.Accent
	}

	return lipgloss.NewStyle().
		Width(headW).
		Height(m.bodyHeight()).
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(borderColor)).
		Render(
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
		Foreground(lipgloss.Color(t.Text)).
		Background(lipgloss.Color(t.SurfaceAlt)).
		Bold(true)
	return s
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
	detailContent := lipgloss.NewStyle().
		Width(innerW).
		Padding(1, 2).
		Render(vp.View())

	footer := m.footerHelp(paneDetail, innerW)
	var footerEls []string
	footerEls = append(footerEls, footer)
	if m.toast != "" {
		toastStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true)
		footerEls = append(footerEls, toastStyle.Render(m.toast))
	}
	footerStyled := lipgloss.NewStyle().
		Width(innerW).
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
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
	panelInnerH := m.bodyHeight() - 2 // minus border
	emptyLines := panelInnerH - lipgloss.Height(detailContent) - lipgloss.Height(footerStyled)
	if emptyLines < 0 {
		emptyLines = 0
	}
	body := detailContent + strings.Repeat("\n", emptyLines) + footerStyled

	return lipgloss.NewStyle().
		Width(m.detailWidth()).
		Height(m.bodyHeight()).
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(borderColor)).
		Render(body)
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

	metaRows := []string{
		muted.Render(fmt.Sprintf("%-12s", "ID")) + text.Render(f.ID),
		muted.Render(fmt.Sprintf("%-12s", "Source")) + text.Render(f.Source.String()),
		muted.Render(fmt.Sprintf("%-12s", "Remediation")) + text.Render(remediationShortLabel(f.Remediation)),
	}
	if f.Service != "" {
		metaRows = append(metaRows, muted.Render(fmt.Sprintf("%-12s", "Service"))+text.Render(f.Service))
	}
	meta := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
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
			block := lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color(t.Border)).
				Padding(0, 1).
				Width(width).
				Render(muted.Render(k) + "\n" + text.Render(lipgloss.Wrap(f.Evidence[k], max(1, width-2), " ")))
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
			block := lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color(t.Border)).
				Padding(0, 1).
				Width(width).
				Render(muted.Render(k) + "\n" + text.Render(lipgloss.Wrap(f.Metadata[k], max(1, width-2), " ")))
			b.WriteString(block + "\n")
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
			"  e             Export report (JSON/CSV)",
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
			"  e             Export report (JSON/CSV)",
			"  Ctrl+R        Recalculate score",
			"  Ctrl+S        Rescan all tools",
			"  Ctrl+A        Select/deselect all visible",
			"  ?             This help",
			"  q             Quit",
		)
	}
	lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("Press q, esc, ? or enter to close"))

	return s.Width(clamp(m.width-8, 48, 80)).Render(strings.Join(lines, "\n"))
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
		lipgloss.NewStyle().Bold(true).Render(label),
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
			style := lipgloss.NewStyle()
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

	return s.Width(clamp(m.width-8, 48, 80)).Render(strings.Join(lines, "\n"))
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

func (m model) renderFixProgressModal() string {
	t := m.theme()
	s := m.modalStyle()

	pct := 0
	if m.fixProgressTotal > 0 {
		pct = m.fixProgress * 100 / m.fixProgressTotal
	}
	barW := 30
	filled := barW * pct / 100
	if filled > barW {
		filled = barW
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barW-filled)

	title := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Bold(true).Render("Applying fixes")
	header := fmt.Sprintf("%d / %d", m.fixProgress, m.fixProgressTotal)
	pctStr := fmt.Sprintf("%d%%", pct)

	barLine := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Accent)).Render(bar)
	pctLine := lipgloss.JoinHorizontal(lipgloss.Top, " ", barLine, " ", pctStr)

	var labelLine string
	if m.fixProgressLabel != "" {
		labelLine = lipgloss.NewStyle().Foreground(lipgloss.Color(t.TextMuted)).Render("  " + m.fixProgressLabel)
	}

	lines := []string{
		title,
		"",
		header,
		pctLine,
	}
	if labelLine != "" {
		lines = append(lines, labelLine)
	}

	return s.Width(clamp(m.width-8, 48, 64)).Render(strings.Join(lines, "\n"))
}

func (m model) renderExportModal() string {
	t := m.theme()
	s := m.modalStyle()

	formats := []string{"JSON (full data)", "CSV (spreadsheet)"}
	var items []string
	for i, f := range formats {
		mark := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(t.Text))
		if i == m.exportIdx {
			mark = "> "
			style = style.Foreground(lipgloss.Color(t.Accent)).Bold(true)
		}
		items = append(items, "  "+mark+style.Render(f))
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
	return s.Width(clamp(m.width-8, 48, 64)).Render(strings.Join(lines, "\n"))
}

func (m model) modalStyle() lipgloss.Style {
	t := m.theme()
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(1, 2)
}

func severityBadgeStr(label, color string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(color)).
		Bold(true).
		Render("[" + label + "]")
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
