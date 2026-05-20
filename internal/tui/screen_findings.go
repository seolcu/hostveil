package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

type findingsModel struct {
	list     []domain.Finding
	all      []domain.Finding
	selected int
	scroll   int
	detailVP viewport.Model

	// Filters
	severityFilter    string
	sourceFilter      string
	scopeFilter       string
	serviceFilter     string
	remediationFilter string
	sortMode          string

	searchQuery       string
	showSearch        bool
	showDetail        bool
	showFixPreview    bool
	fixPreviewContent string
	fixBackupPath     string
	hostTriageMode    bool
	showFilterPanel   bool
	filterCursor      int

	uniqueServices []string
}

type filterRow struct {
	label    string
	value    string
	options  []string
}

var filterPanelRows = []filterRow{
	{label: "Severity", options: []string{"all", "critical", "high", "medium", "low"}},
	{label: "Service", options: nil},
	{label: "Scope", options: []string{"all", "service", "host", "image", "project"}},
	{label: "Fix", options: []string{"all", "auto", "review", "manual"}},
	{label: "Source", options: []string{"all", "native_compose", "native_host", "trivy", "dockle", "lynis", "gitleaks"}},
}

func newFindingsModel(findings []domain.Finding) *findingsModel {
	m := &findingsModel{
		all:      findings,
		selected: 0,
	}
	m.collectUniqueServices()
	m.applyFilters()
	return m
}

func (m *findingsModel) collectUniqueServices() {
	seen := make(map[string]bool)
	for _, f := range m.all {
		if f.Service != "" && !seen[f.Service] {
			seen[f.Service] = true
			m.uniqueServices = append(m.uniqueServices, f.Service)
		}
	}
	sort.Strings(m.uniqueServices)
	// Update filter panel services
	for i := range filterPanelRows {
		if filterPanelRows[i].label == "Service" {
			filterPanelRows[i].options = append([]string{"all"}, m.uniqueServices...)
			break
		}
	}
}

func (m *findingsModel) applyFilters() {
	m.list = make([]domain.Finding, 0)
	for _, f := range m.all {
		if m.severityFilter != "" && f.Severity.String() != m.severityFilter {
			continue
		}
		if m.sourceFilter != "" && f.Source.String() != m.sourceFilter {
			continue
		}
		if m.scopeFilter != "" && f.Scope.String() != m.scopeFilter {
			continue
		}
		if m.serviceFilter != "" && f.Service != m.serviceFilter {
			continue
		}
		if m.remediationFilter != "" && f.Remediation.String() != m.remediationFilter {
			continue
		}
		if m.searchQuery != "" {
			q := strings.ToLower(m.searchQuery)
			if !strings.Contains(strings.ToLower(f.Title), q) &&
				!strings.Contains(strings.ToLower(f.Description), q) {
				continue
			}
		}
		m.list = append(m.list, f)
	}

	switch m.sortMode {
	case "severity":
		sort.Slice(m.list, func(i, j int) bool {
			if m.list[i].Severity != m.list[j].Severity {
				return m.list[i].Severity < m.list[j].Severity
			}
			return m.list[i].Title < m.list[j].Title
		})
	case "source":
		sort.Slice(m.list, func(i, j int) bool {
			if m.list[i].Source.String() != m.list[j].Source.String() {
				return m.list[i].Source.String() < m.list[j].Source.String()
			}
			return m.list[i].Severity < m.list[j].Severity
		})
	case "title":
		sort.Slice(m.list, func(i, j int) bool {
			if m.list[i].Title != m.list[j].Title {
				return m.list[i].Title < m.list[j].Title
			}
			return m.list[i].Severity < m.list[j].Severity
		})
	}

	if m.selected >= len(m.list) {
		m.selected = 0
	}
}

func (m *findingsModel) Update(msg tea.Msg) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		s := msg.String()

		// Search mode takes priority
		if m.showSearch {
			switch s {
			case "esc":
				m.showSearch = false
				m.searchQuery = ""
				m.applyFilters()
			case "enter":
				m.showSearch = false
			case "backspace":
				if len(m.searchQuery) > 0 {
					runes := []rune(m.searchQuery)
					m.searchQuery = string(runes[:len(runes)-1])
					m.applyFilters()
				}
			default:
				if len(msg.Runes) > 0 {
					m.searchQuery += string(msg.Runes)
					m.applyFilters()
				}
			}
			return
		}

		// Filter panel mode
		if m.showFilterPanel {
			switch s {
			case "f", "esc":
				m.showFilterPanel = false
			case "j", "down":
				m.filterCursor++
				if m.filterCursor >= len(filterPanelRows) {
					m.filterCursor = 0
				}
			case "k", "up":
				m.filterCursor--
				if m.filterCursor < 0 {
					m.filterCursor = len(filterPanelRows) - 1
				}
			case "l", "right", "enter":
				m.cycleFilterValue(1)
			case "h", "left":
				m.cycleFilterValue(-1)
			case "r":
				m.resetFilters()
				m.showFilterPanel = false
			}
			return
		}

		switch s {
		case "j", "down":
			if m.showDetail {
				m.detailVP.LineDown(1)
			} else {
				m.selected++
				if m.selected >= len(m.list) {
					m.selected = len(m.list) - 1
				}
			}
		case "k", "up":
			if m.showDetail {
				m.detailVP.LineUp(1)
			} else {
				m.selected--
				if m.selected < 0 {
					m.selected = 0
				}
			}
		case "enter", "l", "right":
			m.showDetail = !m.showDetail
			if m.showDetail && m.selected < len(m.list) {
				f := m.list[m.selected]
				m.detailVP = viewport.New(60, 20)
				m.detailVP.SetContent(formatFindingDetail(&f))
			}
		case "h", "left":
			m.showDetail = false
		case "s":
			m.cycleSort()
		case "f":
			if !m.showDetail {
				m.showFilterPanel = true
				m.filterCursor = 0
			}
		case "/":
			m.showSearch = true
		case "esc":
			m.showSearch = false
			m.showDetail = false
			m.showFilterPanel = false
			m.searchQuery = ""
			m.applyFilters()
		}
	}
}

func (m *findingsModel) cycleFilterValue(dir int) {
	if m.filterCursor >= len(filterPanelRows) {
		return
	}
	row := &filterPanelRows[m.filterCursor]
	if len(row.options) <= 1 {
		return
	}

	current := row.value
	if current == "" {
		current = row.options[0]
	}

	idx := -1
	for i, o := range row.options {
		if o == current {
			idx = i
			break
		}
	}
	if idx < 0 {
		idx = 0
	}

	newIdx := (idx + dir + len(row.options)) % len(row.options)
	row.value = row.options[newIdx]

	// Apply the filter value
	switch row.label {
	case "Severity":
		if row.value == "all" {
			m.severityFilter = ""
		} else {
			m.severityFilter = row.value
		}
	case "Service":
		if row.value == "all" {
			m.serviceFilter = ""
		} else {
			m.serviceFilter = row.value
		}
	case "Scope":
		if row.value == "all" {
			m.scopeFilter = ""
		} else {
			m.scopeFilter = row.value
		}
	case "Fix":
		if row.value == "all" {
			m.remediationFilter = ""
		} else {
			m.remediationFilter = row.value
		}
	case "Source":
		if row.value == "all" {
			m.sourceFilter = ""
		} else {
			m.sourceFilter = row.value
		}
	}
	m.applyFilters()
}

func (m *findingsModel) cycleSort() {
	m.sortMode = nextCycle(m.sortMode, []string{"severity", "source", "title"})
	m.applyFilters()
}

func (m *findingsModel) resetFilters() {
	m.severityFilter = ""
	m.sourceFilter = ""
	m.scopeFilter = ""
	m.serviceFilter = ""
	m.remediationFilter = ""
	m.sortMode = "severity"
	m.searchQuery = ""
	m.showSearch = false
	m.selected = 0
	m.hostTriageMode = false
	m.showFixPreview = false
	m.fixPreviewContent = ""
	m.fixBackupPath = ""
	m.showFilterPanel = false
	// Reset filter panel row values
	for i := range filterPanelRows {
		filterPanelRows[i].value = ""
	}
	m.applyFilters()
}

func nextCycle(current string, options []string) string {
	for i, o := range options {
		if o == current {
			return options[(i+1)%len(options)]
		}
	}
	return options[0]
}

func formatFindingDetail(f *domain.Finding) string {
	var b strings.Builder

	// Title
	b.WriteString(fmt.Sprintf("%s\n\n", f.Title))

	// Severity + Remediation
	sevRem := fmt.Sprintf("%s · %s",
		strings.ToUpper(f.Severity.String()),
		f.Remediation.Label())
	b.WriteString(fmt.Sprintf("%s\n\n", sevRem))

	// Description (Impact)
	if f.Description != "" {
		b.WriteString("Impact:\n")
		b.WriteString(f.Description + "\n\n")
	}

	// Why it's risky
	if f.WhyRisky != "" {
		b.WriteString("Why it matters:\n")
		b.WriteString(f.WhyRisky + "\n\n")
	}

	// Evidence
	if len(f.Evidence) > 0 {
		b.WriteString("Evidence:\n")
		for k, v := range f.Evidence {
			b.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
		b.WriteString("\n")
	}

	// Recommended fix
	if f.HowToFix != "" {
		b.WriteString("Recommended fix:\n")
		b.WriteString(f.HowToFix + "\n\n")
	}

	// Metadata (bottom)
	b.WriteString("───  Metadata  ───\n")
	b.WriteString(fmt.Sprintf("ID: %s  |  Source: %s  |  Scope: %s\n",
		f.ID, f.Source.String(), f.Scope.String()))

	return b.String()
}

func highlightText(s, query string) string {
	if query == "" {
		return s
	}
	q := strings.ToLower(query)
	lower := strings.ToLower(s)
	var result strings.Builder
	start := 0
	for {
		idx := strings.Index(lower[start:], q)
		if idx == -1 {
			result.WriteString(s[start:])
			break
		}
		result.WriteString(s[start : start+idx])
		result.WriteString("\x1b[7m" + s[start+idx:start+idx+len(q)] + "\x1b[27m")
		start = start + idx + len(q)
	}
	return result.String()
}

func (m *findingsModel) render(theme Theme, width, height int) string {
	if width < 20 {
		return "Terminal too narrow"
	}

	if width < miniWidth {
		return m.renderMiniFindings(theme, width)
	}

	lm := layoutMode(width, height)
	if lm == LayoutUltraWide || lm == LayoutWide {
		return m.renderUltraWideFindings(theme, width, height)
	}

	filterBar := m.renderFilterBar(theme, width)

	listWidth := width
	previewWidth := 0
	if m.showDetail {
		listWidth = width / 2
	} else if width >= wideWidth && len(m.list) > 0 {
		listWidth = width * 2 / 3
		previewWidth = width - listWidth - 1
	}
	listHeight := height - 2

	var listContent strings.Builder
	listContent.WriteString(filterBar + "\n")

	if len(m.list) == 0 {
		listContent.WriteString(m.renderEmptyFindingsState(theme, listWidth, listHeight))
	} else {
		m.renderFindingsList(theme, &listContent, listWidth, listHeight, previewWidth == 0 && !m.showDetail)
	}

	if m.showDetail && m.selected < len(m.list) {
		f := m.list[m.selected]
		detail := m.renderDetailContent(&f, theme, listWidth, listHeight)
		detailStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(theme.Border)).
			Width(listWidth).
			Padding(0, 1).
			Height(listHeight)
		detailPanel := detailStyle.Render(detail)
		listStyle := lipgloss.NewStyle().
			Width(listWidth).
			Height(listHeight)
		return lipgloss.JoinHorizontal(lipgloss.Top,
			listStyle.Render(listContent.String()),
			detailPanel,
		)
	}

	if previewWidth > 0 && m.selected < len(m.list) {
		previewPanel := m.renderWidePreviewPanel(theme, previewWidth, listHeight)
		listStyle := lipgloss.NewStyle().
			Width(listWidth).
			Height(listHeight)
		return lipgloss.JoinHorizontal(lipgloss.Top,
			listStyle.Render(listContent.String()),
			previewPanel,
		)
	}

	if m.showFilterPanel && !m.showDetail {
		panel := m.renderFilterPanel(theme, listWidth, listHeight)
		panelLines := strings.Count(panel, "\n") + 1
		padTop := (listHeight - panelLines) / 2
		if padTop < 0 {
			padTop = 0
		}
		return strings.Repeat("\n", padTop) + panel
	}

	return listContent.String()
}

func (m *findingsModel) renderUltraWideFindings(theme Theme, width, height int) string {
	filterBar := m.renderFilterBar(theme, width)

	listWidth := width * 2 / 5
	previewWidth := width - listWidth - 1
	bottomHeight := 6
	mainHeight := height - 2 - bottomHeight - 2

	var listContent strings.Builder
	listContent.WriteString(filterBar + "\n")

	if len(m.list) == 0 {
		listContent.WriteString(m.renderEmptyFindingsState(theme, listWidth, mainHeight))
	} else {
		m.renderFindingsList(theme, &listContent, listWidth, mainHeight, false)
	}

	var topRow string
	listStyle := lipgloss.NewStyle().
		Width(listWidth).
		Height(mainHeight)

	if len(m.list) == 0 {
		preview := m.renderCleanFindingsState(theme, previewWidth, mainHeight)
		topRow = lipgloss.JoinHorizontal(lipgloss.Top,
			listStyle.Render(listContent.String()),
			preview,
		)
	} else if m.showDetail && m.selected < len(m.list) {
		f := m.list[m.selected]
		detail := m.renderDetailContent(&f, theme, previewWidth, mainHeight)
		detailStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(theme.Border)).
			Width(previewWidth).
			Padding(0, 1).
			Height(mainHeight)
		topRow = lipgloss.JoinHorizontal(lipgloss.Top,
			listStyle.Render(listContent.String()),
			detailStyle.Render(detail),
		)
	} else {
		preview := m.renderWidePreviewPanel(theme, previewWidth, mainHeight)
		topRow = lipgloss.JoinHorizontal(lipgloss.Top,
			listStyle.Render(listContent.String()),
			preview,
		)
	}

	bottomCards := m.renderFindingsBottomCards(theme, listWidth, previewWidth)
	fixGuidance := m.renderFixGuidance(theme, width)

	return joinRows(
		topRow,
		"",
		bottomCards,
		fixGuidance,
	)
}

func (m *findingsModel) renderEmptyFindingsState(theme Theme, width, height int) string {
	var icon string
	var msgLines []string
	var help string

	switch {
	case m.hostTriageMode:
		icon = "○"
		msgLines = []string{"No host-level findings detected.", "All findings from this scan are service-level."}
		help = "Press r to clear filters"
	case len(m.all) == 0:
		icon = "✓"
		msgLines = []string{"No findings detected.", "Your current scan passed all enabled checks."}
		help = "Press 3 to export a clean report"
	default:
		icon = "·"
		msgLines = []string{"No findings match current filters."}
		help = "Press r to clear filters"
	}
	msg := strings.Join(msgLines, "\n")

	padding := strings.Repeat("\n", (height-6)/2)
	iconStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Border)).
		Render(icon)
	centerMsg := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render(msg)
	centerHelp := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render(help)

	var b strings.Builder
	b.WriteString(padding)
	b.WriteString(lipgloss.PlaceHorizontal(width, lipgloss.Center, iconStyle) + "\n\n")
	b.WriteString(lipgloss.PlaceHorizontal(width, lipgloss.Center, centerMsg) + "\n")
	b.WriteString(lipgloss.PlaceHorizontal(width, lipgloss.Center, centerHelp))
	return b.String()
}

func (m *findingsModel) renderCleanFindingsState(theme Theme, width, height int) string {
	cardStyle := lipgloss.NewStyle().
		Width(width).
		Height(height).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(theme.Success)).
		Render("Clean scan meaning")

	lines := []string{
		"  All enabled checks passed.",
		"",
		"  Coverage",
		"  Services: none",
		"  Compose file: not found",
		"  Host checks: enabled",
	}

	return cardStyle.Render(title + "\n" + strings.Join(lines, "\n"))
}

func (m *findingsModel) renderFindingsList(theme Theme, b *strings.Builder, listWidth, listHeight int, showHints bool) {
	for i, f := range m.list {
		cursor := " "
		if i == m.selected {
			cursor = ">"
		}

		color := f.Severity.Color()
		icon := severityIcon(f.Severity)
		idxStr := fmt.Sprintf("%2d.", i+1)
		sevLabel := fmt.Sprintf("%s %s", icon, strings.ToUpper(f.Severity.String()))

		title := f.Title
		if m.searchQuery != "" {
			titleMatch := strings.Contains(strings.ToLower(f.Title), strings.ToLower(m.searchQuery))
			if titleMatch {
				title = highlightText(title, m.searchQuery)
			} else if strings.Contains(strings.ToLower(f.Description), strings.ToLower(m.searchQuery)) {
				title += "…"
			}
		}
		title = truncateStr(title, listWidth-36)

		line := fmt.Sprintf("%s  %s  %s %s  %s", cursor, idxStr, sevLabel, title, f.Service)

		style := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
		if i == m.selected {
			style = style.Bold(true).Background(lipgloss.Color(theme.Surface))
		}

		b.WriteString(style.Render(line) + "\n")
	}

	if showHints && len(m.list) > 0 {
		remaining := listHeight - len(m.list) - 1
		if remaining > 3 {
			sepLine := "\n" + strings.Repeat("─", listWidth)
			b.WriteString(sepLine + "\n")

			var sevParts []string
			for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
				count := 0
				for _, f := range m.list {
					if f.Severity == sev {
						count++
					}
				}
				if count > 0 {
					col := sev.Color()
					sevParts = append(sevParts,
						lipgloss.NewStyle().Foreground(lipgloss.Color(col)).Render(fmt.Sprintf("%s: %d", strings.ToUpper(sev.String()), count)),
					)
				}
			}
			if len(sevParts) > 0 {
				b.WriteString("  " + strings.Join(sevParts, "  ") + "\n")
			}

			hint := "Enter/l detail  |  / search  |  f filter  |  s sort  |  r reset"
			b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render(hint) + "\n")
		}
	}
}

func (m *findingsModel) renderFindingsBottomCards(theme Theme, leftWidth, rightWidth int) string {
	filterState := m.renderFilterStateCard(theme, leftWidth)
	related := m.renderRelatedFindingsCard(theme, rightWidth)
	return lipgloss.JoinHorizontal(lipgloss.Top, filterState, "  ", related)
}

func (m *findingsModel) renderFilterStateCard(theme Theme, width int) string {
	var lines []string
	addLine := func(k, v string) {
		if v == "" {
			v = "All"
		}
		lines = append(lines, fmt.Sprintf("  %-12s %s", k+":", v))
	}

	sev := m.severityFilter
	if sev == "" {
		sev = "All"
	} else {
		sev = naturalSeverity(sev)
	}
	addLine("Severity", sev)

	svc := m.serviceFilter
	if svc == "" {
		svc = "All"
	}
	addLine("Service", svc)

	scope := m.scopeFilter
	if scope == "" {
		scope = "All"
	} else {
		scope = naturalScope(scope)
	}
	addLine("Scope", scope)

	fix := m.remediationFilter
	if fix == "" {
		fix = "All"
	} else {
		fix = naturalRemediation(fix)
	}
	addLine("Fix", fix)

	src := m.sourceFilter
	if src == "" {
		src = "All"
	} else {
		src = naturalSource(src)
	}
	addLine("Source", src)

	return renderCard("Filter state", strings.Join(lines, "\n"), theme, width, 0)
}

func (m *findingsModel) renderRelatedFindingsCard(theme Theme, width int) string {
	if len(m.list) == 0 || m.selected >= len(m.list) {
		return renderCard("Related findings", "  No finding selected.", theme, width, 0)
	}
	f := m.list[m.selected]
	svc := f.Service
	if svc == "" {
		return renderCard("Related findings", "  No service context.", theme, width, 0)
	}

	related := m.relatedFindings(&f)
	if len(related) == 0 {
		// Show same-service findings instead
		var sameSvc []domain.Finding
		for _, o := range m.all {
			if o.Service == svc && o.ID != f.ID {
				sameSvc = append(sameSvc, o)
			}
		}
		if len(sameSvc) == 0 {
			return renderCard("Related findings", "  No related findings.", theme, width, 0)
		}
		var lines []string
		maxShow := 4
		for i, rf := range sameSvc {
			if i >= maxShow {
				break
			}
			icon := severityIcon(rf.Severity)
			title := truncateStr(rf.Title, width-12)
			lines = append(lines, fmt.Sprintf("  %s %s", icon, title))
		}
		return renderCard(fmt.Sprintf("Same service: %s", svc), strings.Join(lines, "\n"), theme, width, 0)
	}

	var lines []string
	for _, rf := range related {
		icon := severityIcon(rf.Severity)
		title := truncateStr(rf.Title, width-12)
		lines = append(lines, fmt.Sprintf("  %s %s", icon, title))
	}
	return renderCard(fmt.Sprintf("Same service: %s", svc), strings.Join(lines, "\n"), theme, width, 0)
}

func (m *findingsModel) renderFixGuidance(theme Theme, width int) string {
	if len(m.list) == 0 || m.selected >= len(m.list) {
		return renderCard("Fix guidance", "  No finding selected.", theme, width, 0)
	}
	f := m.list[m.selected]
	var guidance string
	switch f.Remediation {
	case domain.RemediationAuto:
		guidance = "This finding can be auto-fixed. Press p to preview the change, then a to apply."
	case domain.RemediationReview:
		guidance = "This finding requires review. Press p to preview the suggested change. Apply only after verifying correctness."
	default:
		guidance = "This finding requires manual intervention. Follow the recommended fix steps above."
	}
	return renderCard("Fix guidance", "  "+guidance, theme, width, 0)
}

func (m *findingsModel) renderDetailContent(f *domain.Finding, theme Theme, width, height int) string {
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(f.Severity.Color())).
		Bold(true)

	if m.showFixPreview && m.fixPreviewContent != "" {
		return m.renderFixPreviewContent(f, theme, width)
	}

	sep := "\n" + strings.Repeat("═", width-4) + "\n"
	detail := headerStyle.Render(f.Title) + "\n\n"

	sevRem := fmt.Sprintf("%s · %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color(f.Severity.Color())).Render(strings.ToUpper(f.Severity.String())),
		f.Remediation.Label())
	detail += sevRem + "\n\n"

	if f.Description != "" {
		detail += fmt.Sprintf("Impact:\n%s\n\n", f.Description)
	}
	if f.WhyRisky != "" {
		detail += fmt.Sprintf("Why it matters:\n%s\n\n", f.WhyRisky)
	}
	if len(f.Evidence) > 0 {
		detail += "Evidence:\n"
		for k, v := range f.Evidence {
			detail += fmt.Sprintf("  %s: %s\n", k, v)
		}
		detail += "\n"
	}
	if f.HowToFix != "" {
		detail += fmt.Sprintf("Recommended fix:\n%s\n\n", f.HowToFix)
	}
	if f.IsFixable() {
		detail += lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Accent)).Render("p preview fix") + "\n"
	}

	detail += sep
	detail += fmt.Sprintf("ID: %s  |  Source: %s  |  Scope: %s  |  Service: %s",
		f.ID, f.Source.String(), f.Scope.String(), f.Service)

	detail += "\n\n───  Actions  ───\n"
	if f.IsFixable() {
		detail += "p  Preview fix\n"
		if f.Source == domain.SourceNativeCompose {
			detail += "a  Apply after preview\n"
		}
	}
	detail += "r  Rescan\n"
	detail += "Esc  Back to list"

	related := m.relatedFindings(f)
	if len(related) > 0 {
		detail += "\n\n───  Related findings  ───\n"
		for _, rf := range related {
			icon := severityIcon(rf.Severity)
			detail += fmt.Sprintf("  %s %s\n", icon, rf.Title)
		}
	}

	return detail
}

func (m *findingsModel) renderFixPreviewContent(f *domain.Finding, theme Theme, width int) string {
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(f.Severity.Color())).
		Bold(true)
	sep := "\n" + strings.Repeat("═", width-4) + "\n"

	detail := headerStyle.Render(fmt.Sprintf("Fix Preview: %s", f.Title)) + "\n\n"
	detail += "Current setup:\n"
	detail += m.fixPreviewContent
	if m.fixBackupPath != "" {
		detail += fmt.Sprintf("\nBackup: %s\n", m.fixBackupPath)
	}
	detail += "\n───  Decision  ───\n"
	switch f.Remediation {
	case domain.RemediationAuto:
		detail += "This change can be applied automatically.\n"
	case domain.RemediationReview:
		detail += "This change requires review before applying.\n"
	default:
		detail += "This change must be applied manually.\n"
	}
	if m.fixBackupPath != "" {
		detail += fmt.Sprintf("Backup will be created: %s\n", m.fixBackupPath)
	} else {
		detail += "No backup path available.\n"
	}
	detail += "\n"
	detail += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Accent)).Render("[p] Close preview") + "\n"
	if f.Remediation != domain.RemediationManual {
		detail += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Success)).Render("[a] Apply fix") + "\n"
	}
	detail += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.TextMuted)).Render("[r] Rescan after manual change")
	detail += sep
	return detail
}

func (m *findingsModel) renderWidePreviewPanel(theme Theme, width, height int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Height(height).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	if m.selected >= len(m.list) {
		emptyText := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("No finding selected")
		return style.Render(emptyText)
	}

	f := m.list[m.selected]

	var b strings.Builder

	sevColor := f.Severity.Color()
	sevStr := strings.ToUpper(f.Severity.String())
	sevTag := lipgloss.NewStyle().Foreground(lipgloss.Color(sevColor)).Bold(true).Render(sevStr)
	remLabel := f.Remediation.Label()
	remColor := remediationColor(f.Remediation, theme)
	remTag := lipgloss.NewStyle().Foreground(lipgloss.Color(remColor)).Render(remLabel)
	b.WriteString(fmt.Sprintf("%s  ·  %s\n\n", sevTag, remTag))

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text))
	b.WriteString(titleStyle.Render(f.Title) + "\n\n")

	if len(f.Evidence) > 0 {
		b.WriteString("Evidence:\n")
		count := 0
		for k, v := range f.Evidence {
			if count >= 2 {
				break
			}
			b.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
			count++
		}
		if len(f.Evidence) > 2 {
			b.WriteString(fmt.Sprintf("  … and %d more\n", len(f.Evidence)-2))
		}
		b.WriteString("\n")
	}

	if f.HowToFix != "" {
		b.WriteString("Recommended:\n")
		truncatedFix := truncateStr(f.HowToFix, width-6)
		b.WriteString("  " + truncatedFix + "\n\n")
	}

	hint := "Enter full detail"
	if f.IsFixable() {
		hint = "p preview fix  ·  " + hint
	}
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Accent))
	b.WriteString(hintStyle.Render(hint))

	return style.Render(b.String())
}

func (m *findingsModel) relatedFindings(f *domain.Finding) []domain.Finding {
	svc := f.Service
	if svc == "" {
		return nil
	}

	type scoredFindings struct {
		finding domain.Finding
		score   int
	}
	var candidates []scoredFindings
	for _, other := range m.all {
		if other.Service != svc || other.ID == f.ID {
			continue
		}
		s := 0
		if other.Axis == f.Axis {
			s += 2
		}
		if other.Remediation == f.Remediation {
			s++
		}
		candidates = append(candidates, scoredFindings{other, s})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].finding.Severity < candidates[j].finding.Severity
	})

	var related []domain.Finding
	for i, c := range candidates {
		if i >= 3 {
			break
		}
		related = append(related, c.finding)
	}
	return related
}

func (m *findingsModel) renderMiniFindings(theme Theme, width int) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Findings: %d/%d\n", len(m.list), len(m.all)))

	if len(m.list) == 0 {
		if len(m.all) == 0 {
			b.WriteString("All clear — no findings detected.\n")
		} else {
			b.WriteString("No findings match current filters.\n")
		}
		b.WriteString("/ search  ·  r reset  ·  q quit")
		return b.String()
	}

	maxShow := 3
	if len(m.list) < maxShow {
		maxShow = len(m.list)
	}
	for i := 0; i < maxShow; i++ {
		f := m.list[i]
		icon := severityIcon(f.Severity)
		title := truncateStr(f.Title, width-10)
		b.WriteString(fmt.Sprintf("%s %s\n", icon, title))
	}

	if len(m.list) > maxShow {
		b.WriteString(fmt.Sprintf("… and %d more\n", len(m.list)-maxShow))
	}

	b.WriteString("/ search  ·  f filters  ·  ? help  ·  q quit")
	return b.String()
}

func (m *findingsModel) renderFilterPanel(theme Theme, panelWidth, panelHeight int) string {
	// Calculate dialog dimensions
	dialogWidth := 44
	if dialogWidth > panelWidth-4 {
		dialogWidth = panelWidth - 4
	}
	if dialogWidth < 36 {
		dialogWidth = 36
	}

	dialogStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(theme.Surface)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Width(dialogWidth).
		Padding(1, 2)

	var content strings.Builder
	content.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(theme.Text)).
		Render("Filters") + "\n\n")

	for i, row := range filterPanelRows {
		cursor := " "
		if i == m.filterCursor {
			cursor = "❯"
		}

		label := lipgloss.NewStyle().
			Width(12).
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(row.label + ":")

		val := row.value
		if val == "" {
			val = "all"
		}
		valDisplay := naturalFilterValue(row.label, val)
		valStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextBright))
		if i == m.filterCursor {
			valStyle = valStyle.Bold(true).Background(lipgloss.Color(theme.Card))
		}

		content.WriteString(fmt.Sprintf("%s %s %s\n", cursor, label, valStyle.Render(valDisplay)))
	}

	content.WriteString("\n")
	content.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("j/k move  ·  ←/→ cycle  ·  f/esc close  ·  r reset"))

	return dialogStyle.Render(content.String())
}

func naturalFilterValue(label, value string) string {
	switch {
	case value == "all":
		return "All"
	case label == "Severity":
		return naturalSeverity(value)
	case label == "Source":
		return naturalSource(value)
	case label == "Scope":
		return naturalScope(value)
	case label == "Fix":
		return naturalRemediation(value)
	default:
		return value
	}
}

func naturalSeverity(s string) string {
	switch s {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return s
}

func naturalSource(s string) string {
	switch s {
	case "native_compose":
		return "Compose"
	case "native_host":
		return "Host"
	}
	return s
}

func naturalScope(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func naturalRemediation(s string) string {
	switch s {
	case "auto":
		return "Auto"
	case "review":
		return "Review"
	case "manual":
		return "Manual"
	}
	return s
}

func (m *findingsModel) renderFilterBar(theme Theme, width int) string {
	var tokens []string
	if m.severityFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Severity: %s", naturalSeverity(m.severityFilter)))
	}
	if m.sourceFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Source: %s", naturalSource(m.sourceFilter)))
	}
	if m.scopeFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Scope: %s", naturalScope(m.scopeFilter)))
	}
	if m.serviceFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Service: %s", m.serviceFilter))
	}
	if m.remediationFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Fix: %s", naturalRemediation(m.remediationFilter)))
	}
	if m.sortMode != "" && m.sortMode != "severity" {
		tokens = append(tokens, fmt.Sprintf("Sort: %s ↑", m.sortMode))
	}

	info := fmt.Sprintf("%d/%d findings", len(m.list), len(m.all))
	if len(tokens) > 0 {
		filterLine := strings.Join(tokens, " | ")
		if lipgloss.Width(info)+lipgloss.Width(filterLine)+7 > width {
			info += "\n" + strings.Repeat(" ", 6) + filterLine
		} else {
			info += "  |  " + filterLine
		}
	}

	if m.showSearch {
		s := "search: Type to search, Esc to cancel"
		if m.searchQuery != "" {
			s = fmt.Sprintf("search: %s█", m.searchQuery)
		}
		if lipgloss.Width(info)+lipgloss.Width(s)+7 > width {
			info += "\n" + strings.Repeat(" ", 6) + s
		} else {
			info += " | " + s
		}
	}

	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Width(width)

	return style.Render(info)
}

func truncateStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}
