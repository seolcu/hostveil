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

	// Fix preview hint
	if f.IsFixable() {
		b.WriteString("p preview fix\n\n")
	}

	// Metadata (bottom)
	b.WriteString("───  Metadata  ───\n")
	b.WriteString(fmt.Sprintf("ID: %s  |  Source: %s  |  Scope: %s  |  Service: %s\n",
		f.ID, f.Source.String(), f.Scope.String(), f.Service))

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
		cols := splitColumns(width, 2, 1)
		listWidth = cols[0]
		previewWidth = cols[1]
	} else if width >= wideWidth && len(m.list) > 0 {
		listWidth = width * 2 / 3
		previewWidth = width - listWidth - 1
	}
	listHeight := height - 2

	// Filter panel dialog overrides normal layout
	if m.showFilterPanel && !m.showDetail {
		panel := m.renderFilterPanel(theme, listWidth, listHeight)
		panelLines := strings.Count(panel, "\n") + 1
		padTop := (listHeight - panelLines) / 2
		if padTop < 0 {
			padTop = 0
		}
		return filterBar + "\n" + strings.Repeat("\n", padTop) + panel
	}

	// Build list panel with border and title
	var listContent strings.Builder
	if len(m.list) == 0 {
		listContent.WriteString(m.renderEmptyFindingsState(theme, listWidth, listHeight))
	} else {
		m.renderFindingsList(theme, &listContent, listWidth, listHeight, false)
	}
	listTitle := fmt.Sprintf("Findings %d/%d", len(m.list), len(m.all))
	listPanel := renderCardBounded(listTitle, listContent.String(), theme, Rect{W: listWidth, H: listHeight})

	// Detail or preview panel (right column)
	var detailContent string
	if m.showDetail && m.selected < len(m.list) {
		f := m.list[m.selected]
		detail := m.renderDetailContent(&f, theme, previewWidth, listHeight)
		detailContent = renderCardBounded("", detail, theme, Rect{W: previewWidth, H: listHeight})
	} else if previewWidth > 0 && m.selected < len(m.list) {
		detailContent = m.renderWidePreviewPanel(theme, previewWidth, listHeight)
	}

	// Top row: list + detail side by side
	var topRow string
	if detailContent != "" {
		topRow = joinColumns([]string{listPanel, detailContent}, []int{listWidth, previewWidth}, 1)
	} else {
		topRow = listPanel
	}

	// Empty state: no bottom cards needed
	if len(m.list) == 0 {
		return filterBar + "\n" + topRow
	}

	// 3-row inspector layout
	cols := splitColumns(width, 2, 2)
	filterCard := m.renderFilterStateCard(theme, cols[0])
	contextCard := m.renderRelatedFindingsCard(theme, cols[1])
	midRow := joinColumns([]string{filterCard, contextCard}, cols, 2)

	guidance := m.renderFixGuidance(theme, width)

	return joinRows(
		filterBar,
		topRow,
		"",
		midRow,
		"",
		guidance,
	)
}

func (m *findingsModel) renderUltraWideFindings(theme Theme, width, height int) string {
	if len(m.all) == 0 {
		return m.renderCleanFindingsUltraWide(theme, width, height)
	}

	filterBar := m.renderFilterBar(theme, width)

	cols := splitColumns(width, 2, 1)
	listWidth := cols[0]
	previewWidth := cols[1]
	bottomHeight := 6
	mainHeight := height - 2 - bottomHeight - 2

	listTitle := fmt.Sprintf("Findings %d/%d", len(m.list), len(m.all))
	var listContent strings.Builder
	if len(m.list) == 0 {
		listContent.WriteString(m.renderEmptyFindingsState(theme, listWidth, mainHeight))
	} else {
		m.renderFindingsList(theme, &listContent, listWidth, mainHeight, false)
	}
	listPanel := renderCardBounded(listTitle, listContent.String(), theme, Rect{W: listWidth, H: mainHeight})

	var topRow string
	if len(m.list) == 0 {
		preview := m.renderCleanFindingsState(theme, previewWidth, mainHeight)
		topRow = joinColumns([]string{listPanel, preview}, []int{listWidth, previewWidth}, 1)
	} else if m.showDetail && m.selected < len(m.list) {
		f := m.list[m.selected]
		detail := m.renderDetailContent(&f, theme, previewWidth, mainHeight)
		detailPanel := renderCardBounded("", detail, theme, Rect{W: previewWidth, H: mainHeight})
		topRow = joinColumns([]string{listPanel, detailPanel}, []int{listWidth, previewWidth}, 1)
	} else {
		preview := m.renderWidePreviewPanel(theme, previewWidth, mainHeight)
		topRow = joinColumns([]string{listPanel, preview}, []int{listWidth, previewWidth}, 1)
	}

	bottomCards := m.renderFindingsBottomCards(theme, cols)
	fixGuidance := m.renderFixGuidance(theme, width)

	return joinRows(
		filterBar,
		topRow,
		"",
		bottomCards,
		fixGuidance,
	)
}

func (m *findingsModel) renderCleanFindingsUltraWide(theme Theme, width, height int) string {
	filterBar := m.renderFilterBar(theme, width)

	cols := splitColumns(width, 2, 2)

	left := m.renderCleanFindingsPanel(theme, cols[0], 0)
	right := m.renderCleanScanMeaningPanel(theme, cols[1], 0)
	topRow := joinColumns([]string{left, right}, cols, 2)

	covCard := m.renderCleanScanCoverageCard(theme, cols[0])
	stepsCard := m.renderCleanNextStepsCard(theme, cols[1])
	bottomCards := joinColumns([]string{covCard, stepsCard}, cols, 2)

	guidance := m.renderCleanScanGuidanceStrip(theme, width)

	return joinRows(
		filterBar,
		topRow,
		"",
		bottomCards,
		guidance,
	)
}

func (m *findingsModel) renderCleanFindingsPanel(theme Theme, outerW, height int) string {
	icon := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Success)).
		Bold(true).
		Render("✓ No findings detected")

	msg := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Your current scan passed all enabled checks.")

	hint := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Accent)).
		Render("Press 3 to export a clean report.")

	return renderCardBounded("", icon+"\n\n"+msg+"\n\n"+hint, theme, Rect{W: outerW, H: height})
}

func (m *findingsModel) renderCleanScanMeaningPanel(theme Theme, outerW, height int) string {
	var lines []string
	lines = append(lines, "  All enabled checks passed.")
	lines = append(lines, "")
	lines = append(lines, "  "+lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("This means Hostveil did not detect any issues in the checks that actually ran."))
	lines = append(lines, "")
	lines = append(lines, "  "+lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("If no Compose services were discovered, service-level checks may not have been evaluated."))

	return renderCardBounded("Clean scan meaning", strings.Join(lines, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *findingsModel) renderCleanScanCoverageCard(theme Theme, outerW int) string {
	var lines []string
	addLine := func(k, v string) {
		lines = append(lines, fmt.Sprintf("  %-20s %s", k+":", v))
	}
	addLine("Services scanned", "none")
	addLine("Compose file", "not found")
	addLine("Host checks", "enabled")
	addLine("Image checks", "available")
	addLine("Secret checks", "available")

	return renderCardBounded("Scan coverage", strings.Join(lines, "\n"), theme, Rect{W: outerW})
}

func (m *findingsModel) renderCleanNextStepsCard(theme Theme, outerW int) string {
	steps := []string{
		"1. Press 3 to export a clean report.",
		"2. Add docker-compose.yml to scan service exposure and permissions.",
		"3. Run Hostveil again after adding or changing services.",
	}
	joined := "  " + strings.Join(steps, "\n  ")
	return renderCardBounded("Next steps", joined, theme, Rect{W: outerW})
}

func (m *findingsModel) renderCleanScanGuidanceStrip(theme Theme, outerW int) string {
	text := "No findings were detected. Keep reports for audit/history, and rescan after configuration or Docker changes."
	return renderCardBounded("Clean scan guidance", "  "+text, theme, Rect{W: outerW})
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

func (m *findingsModel) renderCleanFindingsState(theme Theme, outerW, height int) string {
	lines := []string{
		"  All enabled checks passed.",
		"",
		"  Coverage",
		"  Services: none",
		"  Compose file: not found",
		"  Host checks: enabled",
	}
	return renderCardBounded("Clean scan meaning", strings.Join(lines, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *findingsModel) renderFindingsList(theme Theme, b *strings.Builder, listWidth, listHeight int, showHints bool) {
	// Determine if we have room for the service column
	// Minimum overhead: cursor(1) + idx(4) + spaces(4) + sevLabel min(4)
	// With service: adds 1 space + service name (average ~10 chars)
	showService := listWidth > 60
	compactSev := listWidth < 45

	for i, f := range m.list {
		cursor := " "
		if i == m.selected {
			cursor = ">"
		}

		color := f.Severity.Color()
		icon := severityIcon(f.Severity)
		idxStr := fmt.Sprintf("%2d.", i+1)

		var sevLabel string
		if compactSev {
			sevLabel = fmt.Sprintf("%s %s", icon, severityShortLabel(f.Severity))
		} else {
			sevLabel = fmt.Sprintf("%s %s", icon, strings.ToUpper(f.Severity.String()))
		}

		title := f.Title
		if m.searchQuery != "" {
			titleMatch := strings.Contains(strings.ToLower(f.Title), strings.ToLower(m.searchQuery))
			if titleMatch {
				title = highlightText(title, m.searchQuery)
			} else if strings.Contains(strings.ToLower(f.Description), strings.ToLower(m.searchQuery)) {
				title += "…"
			}
		}

		var line string
		if showService {
			overhead := len(cursor) + 2 + len(idxStr) + 2 + len(sevLabel) + 2 + len(f.Service) + 4
			title = truncateStr(title, listWidth-overhead)
			if compactSev && len(f.Service) > 12 {
				f.Service = truncateStr(f.Service, 12)
			}
			line = fmt.Sprintf("%s  %s  %s  %s  %s", cursor, idxStr, sevLabel, title, f.Service)
		} else {
			overhead := len(cursor) + 2 + len(idxStr) + 2 + len(sevLabel) + 2
			title = truncateStr(title, listWidth-overhead)
			line = fmt.Sprintf("%s  %s  %s  %s", cursor, idxStr, sevLabel, title)
		}

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

func (m *findingsModel) renderFindingsBottomCards(theme Theme, cols []int) string {
	filterState := m.renderFilterStateCard(theme, cols[0])
	related := m.renderRelatedFindingsCard(theme, cols[1])
	return joinColumns([]string{filterState, related}, cols, 2)
}

func (m *findingsModel) renderFilterStateCard(theme Theme, outerW int) string {
	allClear := m.severityFilter == "" && m.serviceFilter == "" && m.scopeFilter == "" &&
		m.remediationFilter == "" && m.sourceFilter == "" && m.sortMode == "severity"

	if allClear {
		return renderCardBounded("Filters", "  All filters clear", theme, Rect{W: outerW})
	}

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

	return renderCardBounded("Filter state", strings.Join(lines, "\n"), theme, Rect{W: outerW})
}

func (m *findingsModel) renderRelatedFindingsCard(theme Theme, outerW int) string {
	if len(m.list) == 0 || m.selected >= len(m.list) {
		return renderCardBounded("Context", "  No finding selected.", theme, Rect{W: outerW})
	}
	f := m.list[m.selected]
	svc := f.Service
	if svc == "" {
		body := fmt.Sprintf("  Scope: %s · No service context · Source: %s",
			f.Scope.String(), f.Source.String())
		return renderCardBounded("Context", body, theme, Rect{W: outerW})
	}

	related := m.relatedFindings(&f)
	if len(related) == 0 {
		var sameSvc []domain.Finding
		for _, o := range m.all {
			if o.Service == svc && o.ID != f.ID {
				sameSvc = append(sameSvc, o)
			}
		}
		if len(sameSvc) == 0 {
			return renderCardBounded(fmt.Sprintf("Same service: %s", svc),
				"  No related findings.", theme, Rect{W: outerW})
		}
		var lines []string
		maxShow := 4
		for i, rf := range sameSvc {
			if i >= maxShow {
				break
			}
			icon := severityIcon(rf.Severity)
			title := truncateStr(rf.Title, outerW-12)
			lines = append(lines, fmt.Sprintf("  %s %s", icon, title))
		}
		return renderCardBounded(fmt.Sprintf("Same service: %s", svc), strings.Join(lines, "\n"), theme, Rect{W: outerW})
	}

	var lines []string
	for _, rf := range related {
		icon := severityIcon(rf.Severity)
		title := truncateStr(rf.Title, outerW-12)
		lines = append(lines, fmt.Sprintf("  %s %s", icon, title))
	}
	return renderCardBounded(fmt.Sprintf("Same service: %s", svc), strings.Join(lines, "\n"), theme, Rect{W: outerW})
}

func (m *findingsModel) renderFixGuidance(theme Theme, width int) string {
	if len(m.list) == 0 || m.selected >= len(m.list) {
		return renderCardBounded("Fix guidance", "  No finding selected.", theme, Rect{W: width})
	}
	f := m.list[m.selected]
	var guidance string
	switch {
	case f.Remediation == domain.RemediationAuto && !m.showFixPreview:
		guidance = "Auto-fix preview available. Press p to inspect the diff before applying."
	case f.Remediation == domain.RemediationAuto && m.showFixPreview:
		guidance = "Review the proposed diff. Press a to apply only after verifying correctness."
	case f.Remediation == domain.RemediationReview && !m.showFixPreview:
		guidance = "Review required. Press p to preview the suggested change. Apply only after verifying correctness."
	case f.Remediation == domain.RemediationReview && m.showFixPreview:
		guidance = "Review the proposed diff. Apply manually if correct, then rescan."
	case f.Remediation == domain.RemediationManual:
		guidance = "Manual change required. Follow the recommended fix steps above, then press r to rescan."
	default:
		guidance = "Select a finding to see remediation guidance."
	}
	return renderCardBounded("Fix guidance", "  "+guidance, theme, Rect{W: width})
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
		detail += "  " + lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Accent)).Render("p preview fix") + "\n"
	}

	detail += sep
	detail += fmt.Sprintf("ID: %s  |  Source: %s  |  Scope: %s  |  Service: %s",
		f.ID, f.Source.String(), f.Scope.String(), f.Service)

	return detail
}

func renderFixDecision(f *domain.Finding, hasBackup bool) string {
	reviewReq := f.Remediation == domain.RemediationReview
	manualOnly := f.Remediation == domain.RemediationManual

	var status []string
	if !manualOnly {
		status = append(status, "Auto-fix: available")
		if reviewReq {
			status = append(status, "Review: required")
		} else {
			status = append(status, "No review needed")
		}
	} else {
		status = append(status, "Auto-fix: unavailable")
	}
	if hasBackup {
		status = append(status, "Backup: available")
	} else {
		status = append(status, "Backup: unavailable")
	}

	statusStr := strings.Join(status, " · ")

	var recommended string
	switch {
	case manualOnly:
		recommended = "Apply manually, then press r to rescan."
	case reviewReq && !hasBackup:
		recommended = "Review diff before applying. No backup — use version control."
	case reviewReq && hasBackup:
		recommended = "Review diff, then press a to apply. Backup will be created."
	case !reviewReq && hasBackup:
		recommended = "Apply fix, then rescan. Backup will be created."
	default:
		recommended = "Apply fix, then rescan to verify."
	}

	return statusStr + "\n  → " + recommended
}

func renderFixActions(f *domain.Finding) string {
	switch {
	case f.Remediation == domain.RemediationManual:
		return ""
	case f.Remediation == domain.RemediationReview:
		return "[a] Apply reviewed fix"
	default:
		return "[a] Apply fix"
	}
}

func (m *findingsModel) renderFixPreviewContent(f *domain.Finding, theme Theme, width int) string {
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(f.Severity.Color())).
		Bold(true)
	sep := "\n" + strings.Repeat("═", width-4) + "\n"

	detail := headerStyle.Render(fmt.Sprintf("Fix Preview: %s", f.Title)) + "\n\n"

	// Status block
	detail += renderFixDecision(f, m.fixBackupPath != "") + "\n\n"

	// Current setup
	detail += "Current setup\n"
	detail += m.fixPreviewContent

	// Actions (separator + action buttons)
	detail += "\n───\n"
	detail += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Accent)).Render("[p] Close preview") + "\n"
	if actions := renderFixActions(f); actions != "" {
		detail += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Success)).Render(actions) + "\n"
	}
	rescanLabel := "[r] Rescan"
	if f.Remediation == domain.RemediationManual {
		rescanLabel = "[r] Rescan after manual change"
	}
	detail += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.TextMuted)).Render(rescanLabel)
	detail += sep
	return detail
}

func (m *findingsModel) renderWidePreviewPanel(theme Theme, outerW, height int) string {
	if m.selected >= len(m.list) {
		return renderCardBounded("", "  No finding selected", theme, Rect{W: outerW, H: height})
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
		truncatedFix := truncateStr(f.HowToFix, outerW-6)
		b.WriteString("  " + truncatedFix + "\n\n")
	}

	hint := "Enter full detail"
	if f.IsFixable() {
		hint = "p preview fix  ·  " + hint
	}
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Accent))
	b.WriteString(hintStyle.Render(hint))

	return renderCardBounded("", b.String(), theme, Rect{W: outerW, H: height})
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

	info := fmt.Sprintf("%d findings", len(m.list))
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
