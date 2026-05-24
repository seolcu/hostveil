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
	list            []domain.Finding
	all             []domain.Finding
	selected        int
	scroll          int
	detailVP        viewport.Model
	showDetail      bool
	showFixPreview  bool
	fixPreviewContent string
	fixBackupPath   string
}

func newFindingsModel(findings []domain.Finding) *findingsModel {
	m := &findingsModel{
		all:      findings,
		list:     findings,
		selected: 0,
	}
	sort.Slice(m.list, func(i, j int) bool {
		if m.list[i].Severity != m.list[j].Severity {
			return m.list[i].Severity < m.list[j].Severity
		}
		return m.list[i].Title < m.list[j].Title
	})
	return m
}

func (m *findingsModel) Update(msg tea.Msg) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		s := msg.String()

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
		case "a":
			if m.selected < len(m.list) && m.list[m.selected].IsFixable() {
				m.showFixPreview = !m.showFixPreview
				m.showDetail = false
			}
		case "p":
			if m.selected < len(m.list) && m.list[m.selected].IsFixable() {
				m.showFixPreview = !m.showFixPreview
				m.showDetail = false
			}
		case "esc":
			m.showDetail = false
		}
	}
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

func (m *findingsModel) render(r *domain.ScanResult, theme Theme, width, height int) string {
	if width < 20 {
		return "Terminal too narrow"
	}

	if width < miniWidth {
		return m.renderMiniFindings(theme, width)
	}

	overviewRow := renderOverviewRow(r, theme, width)
	overviewH := strings.Count(overviewRow, "\n") + 1
	findingsH := max(10, height-overviewH)

	lm := layoutMode(width, findingsH)
	if lm == LayoutCompact {
		return joinRowsWithGap(0, overviewRow, m.renderCompactFindings(theme, width, findingsH))
	}

	if len(m.all) == 0 {
		return joinRowsWithGap(0, overviewRow, m.renderCleanFindingsUltraWide(theme, width, findingsH))
	}

	slots := FindingsSlots(width, findingsH)

	listPanel := m.renderFindingsListPanel(theme, slots.List)

	var detailContent string
	if m.showDetail && m.selected < len(m.list) {
		f := m.list[m.selected]
		detail := m.renderDetailContent(&f, theme, slots.Detail.InnerW(), slots.Detail.InnerH())
		detailContent = RenderPanel(slots.Detail, "", detail, theme, OverflowClip)
	} else if slots.Detail.W > 0 && m.selected < len(m.list) {
		detailContent = m.renderWidePreviewPanel(theme, slots.Detail.InnerW(), slots.Detail.InnerH())
		if detailContent != "" {
			detailContent = RenderPanel(slots.Detail, "", detailContent, theme, OverflowClip)
		}
	}

	topRow := joinColumns([]string{listPanel, detailContent}, []int{slots.List.W, slots.Detail.W}, 1)
	if debugLayout {
		assertDisplayWidthLTE(topRow, width)
	}

	return joinRowsWithGap(0, overviewRow, topRow)
}

func (m *findingsModel) renderFindingsListPanel(theme Theme, listRect Rect) string {
	var listContent strings.Builder
	if len(m.list) == 0 {
		listContent.WriteString(m.renderEmptyFindingsState(theme, listRect.InnerW(), listRect.InnerH()))
	} else {
		m.renderFindingsList(theme, &listContent, listRect.InnerW(), listRect.InnerH(), false)
	}
	listTitle := fmt.Sprintf("Findings %d/%d", len(m.list), len(m.all))
	return RenderPanel(listRect, listTitle, listContent.String(), theme, OverflowClip)
}

func (m *findingsModel) renderCleanFindingsUltraWide(theme Theme, width, height int) string {
	cols := splitColumns(width, 2, 2)

	left := m.renderCleanFindingsPanel(theme, cols[0], 7)
	right := m.renderCleanScanMeaningPanel(theme, cols[1], 7)
	topRow := joinColumns([]string{left, right}, cols, 2)

	covCard := m.renderCleanScanCoverageCard(theme, cols[0], 6)
	stepsCard := m.renderCleanNextStepsCard(theme, cols[1], 6)
	bottomCards := joinColumns([]string{covCard, stepsCard}, cols, 2)

	if debugLayout {
		assertDisplayWidthLTE(topRow, width)
		assertDisplayWidthLTE(bottomCards, width)
	}

	return joinRowsWithGap(0,
		topRow,
		bottomCards,
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
		Render("Export options available in the TUI menu.")

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

func (m *findingsModel) renderCleanScanCoverageCard(theme Theme, outerW, height int) string {
	var lines []string
	addLine := func(k, v string) {
		lines = append(lines, fmt.Sprintf("  %-20s %s", k+":", v))
	}
	addLine("Services scanned", "none")
	addLine("Compose file", "not found")
	addLine("Host checks", "enabled")
	addLine("Image checks", "available")
	addLine("Secret checks", "available")

	return renderCardBounded("Scan coverage", strings.Join(lines, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *findingsModel) renderCleanNextStepsCard(theme Theme, outerW, height int) string {
	steps := []string{
		"1. Add docker-compose.yml to scan service exposure and permissions.",
		"2. Run Hostveil again after adding or changing services.",
		"3. Use export from TUI menu to save results.",
	}
	joined := "  " + strings.Join(steps, "\n  ")
	return renderCardBounded("Next steps", joined, theme, Rect{W: outerW, H: height})
}

func (m *findingsModel) renderEmptyFindingsState(theme Theme, width, height int) string {
	var icon string
	var msgLines []string
	var help string

	switch {
	case len(m.all) == 0:
		icon = "✓"
		msgLines = []string{"No findings detected.", "Your current scan passed all enabled checks."}
		help = "No findings detected in current scan"
	default:
		icon = "·"
		msgLines = []string{"No findings match current filters."}
		help = ""
	}
	msg := strings.Join(msgLines, "\n")

	var padding string
	if height >= 7 {
		padding = strings.Repeat("\n", (height-6)/2)
	}
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

		var line string
		if showService {
			overhead := len(cursor) + 2 + len(idxStr) + 2 + len(sevLabel) + 2 + len(f.Service) + 4
			maxTitle := listWidth - overhead
			if maxTitle < 4 {
				maxTitle = 4
			}
			title = truncateWidth(title, maxTitle)
			if compactSev && len(f.Service) > 12 {
				f.Service = truncateStr(f.Service, 12)
			}
			// Truncate service name to prevent overflow
			maxSvc := listWidth - overhead + len(f.Service) - 4
			if maxSvc < 4 {
				maxSvc = 4
			}
			if lipgloss.Width(f.Service) > maxSvc {
				f.Service = truncateWidth(f.Service, maxSvc)
			}
			line = fmt.Sprintf("%s  %s  %s  %s  %s", cursor, idxStr, sevLabel, title, f.Service)
		} else {
			overhead := len(cursor) + 2 + len(idxStr) + 2 + len(sevLabel) + 2
			maxTitle := listWidth - overhead
			if maxTitle < 4 {
				maxTitle = 4
			}
			title = truncateWidth(title, maxTitle)
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

func (m *findingsModel) renderDetailContent(f *domain.Finding, theme Theme, width, height int) string {
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(f.Severity.Color())).
		Bold(true)

	if m.showFixPreview && m.fixPreviewContent != "" {
		return m.renderFixPreviewContent(f, theme, width)
	}

	innerH := height
	headerH := 3 // title + blank + severity·remediation
	actionH := 0
	if f.IsFixable() {
		actionH = 1
	}
	metadataH := 3 // blank + separator + ID line
	reservedH := headerH + actionH + metadataH
	bodyAvailable := innerH - reservedH
	if bodyAvailable < 1 {
		bodyAvailable = 1
	}

	// 1. Header (fixed)
	title := headerStyle.Render(f.Title)
	sevRem := fmt.Sprintf("%s · %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color(f.Severity.Color())).Render(strings.ToUpper(f.Severity.String())),
		f.Remediation.Label())
	header := title + "\n\n" + sevRem

	// 2. Body (fitted to available height)
	body := buildFindingBodyLines(f, width)
	if len(body) > bodyAvailable {
		body = body[:bodyAvailable-1]
		body = append(body, "  "+lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Italic(true).
			Render("Enter full detail for complete text"))
	}

	// 3. Action hint
	var action string
	if f.IsFixable() {
		action = "  " + lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.Accent)).
			Render("p preview fix")
	}

	// 4. Assemble
	sepWidth := width - 4
	if sepWidth < 1 {
		sepWidth = 1
	}
	sep := "\n" + strings.Repeat("═", sepWidth) + "\n"
	metadata := fmt.Sprintf("ID: %s  |  Source: %s  |  Scope: %s  |  Service: %s",
		f.ID, f.Source.String(), f.Scope.String(), f.Service)

	result := header + "\n\n" + strings.Join(body, "\n")
	if action != "" {
		result += "\n" + action
	}

	// Fill remaining lines to push metadata to bottom
	currentLines := strings.Count(result, "\n") + 1
	fillLines := innerH - currentLines - metadataH
	if fillLines > 0 {
		result += strings.Repeat("\n", fillLines)
	}
	result += "\n" + sep
	result += metadata

	return result
}

func buildFindingBodyLines(f *domain.Finding, width int) []string {
	var sections []string
	if f.Description != "" {
		sections = append(sections, "Impact:\n"+f.Description)
	}
	if f.WhyRisky != "" {
		sections = append(sections, "Why it matters:\n"+f.WhyRisky)
	}
	if len(f.Evidence) > 0 {
		var evLines []string
		for k, v := range f.Evidence {
			evLines = append(evLines, fmt.Sprintf("  %s: %s", k, v))
		}
		sections = append(sections, "Evidence:\n"+strings.Join(evLines, "\n"))
	}
	if f.HowToFix != "" {
		sections = append(sections, "Recommended fix:\n"+f.HowToFix)
	}

	var result []string
	for i, s := range sections {
		if i > 0 {
			result = append(result, "")
		}
		result = append(result, strings.Split(s, "\n")...)
	}
	return result
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
	sepWidth := width - 4
	if sepWidth < 1 {
		sepWidth = 1
	}
	sep := "\n" + strings.Repeat("═", sepWidth) + "\n"

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
		return "  No finding selected"
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

	return b.String()
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

	b.WriteString(fmt.Sprintf("Findings %d/%d\n", len(m.list), len(m.all)))

	maxShow := 3
	if len(m.list) < maxShow {
		maxShow = len(m.list)
	}
	for i := 0; i < maxShow; i++ {
		f := m.list[i]
		icon := severityIcon(f.Severity)
		col := f.Severity.Color()
		sev := lipgloss.NewStyle().Foreground(lipgloss.Color(col)).Render(fmt.Sprintf("%s %s", icon, severityShortLabel(f.Severity)))
		title := truncateStr(f.Title, width-8)
		b.WriteString(fmt.Sprintf("%s %s\n", sev, title))
	}

	if len(m.list) > maxShow {
		b.WriteString(fmt.Sprintf("… and %d more\n", len(m.list)-maxShow))
	}

	b.WriteString("/ search  ·  f filters  ·  ? help  ·  q quit")
	return b.String()
}

func (m *findingsModel) renderCompactFindings(theme Theme, width, height int) string {
	var b strings.Builder

	// Header: finding count
	header := fmt.Sprintf("Findings %d/%d", len(m.list), len(m.all))
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(header) + "\n")

	if len(m.list) == 0 {
		if len(m.all) == 0 {
			b.WriteString("All clear — no findings detected.\n")
		} else {
			b.WriteString("No findings match current filters.\n")
		}
		b.WriteString("/ search  ·  r reset  ·  q quit")
		return b.String()
	}

	// Detail toggle mode
	if m.showDetail && m.selected < len(m.list) {
		f := m.list[m.selected]
		sevColor := f.Severity.Color()
		sevStr := strings.ToUpper(f.Severity.String())
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(sevColor)).Bold(true).Render(sevStr+" · "+f.Title) + "\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(sevColor)).Render(f.Remediation.Label()) + "\n\n")

		body := buildFindingBodyLines(&f, width-4)
		for _, line := range body {
			b.WriteString("  " + truncateStr(line, width-2) + "\n")
		}
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("p preview · Esc list · q quit"))
		return b.String()
	}

	// List view: show findings with severity
	maxShow := height - 4
	if maxShow < 1 {
		maxShow = 1
	}
	if len(m.list) < maxShow {
		maxShow = len(m.list)
	}
	for i := 0; i < maxShow; i++ {
		f := m.list[i]
		icon := severityIcon(f.Severity)
		sevLabel := severityShortLabel(f.Severity)
		col := f.Severity.Color()
		cursor := " "
		if i == m.selected {
			cursor = ">"
		}
		sev := lipgloss.NewStyle().Foreground(lipgloss.Color(col)).Render(fmt.Sprintf("%s %s", icon, sevLabel))
		title := truncateStr(f.Title, width-10)
		b.WriteString(fmt.Sprintf("%s %s %s\n", cursor, sev, title))
	}
	if len(m.list) > maxShow {
		b.WriteString(fmt.Sprintf("… and %d more\n", len(m.list)-maxShow))
	}

	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Enter detail · / search · f filter · q quit"))
	return b.String()
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

func severityShortLabel(sev domain.Severity) string {
	switch sev {
	case domain.SeverityCritical:
		return "CRIT"
	case domain.SeverityHigh:
		return "HIGH"
	case domain.SeverityMedium:
		return "MED"
	case domain.SeverityLow:
		return "LOW"
	default:
		return strings.ToUpper(sev.String())
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

func scoreBarContent(r *domain.ScanResult, theme Theme, outerW int) string {
	var rows []string
	barW := clamp(outerW/4, 6, 16)
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
		label := lipgloss.NewStyle().Width(22).Render(axis.Label())
		bar := renderBar(score, barW, scoreColor)
		scoreTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(scoreColor)).
			Width(4).Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", score))
		gradeTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(scoreColor)).
			Render(gradeStr)
		rows = append(rows, fmt.Sprintf("  %s %s %s %s", label, bar, scoreTag, gradeTag))
	}
	return strings.Join(rows, "\n")
}

func scanContextContent(r *domain.ScanResult, theme Theme, outerW int) string {
	var pairs []KV
	info := r.Metadata.HostRuntime
	if info != nil {
		if info.Hostname != "" {
			pairs = append(pairs, KV{"Hostname", info.Hostname})
		}
		if info.DockerVersion != "" {
			pairs = append(pairs, KV{"Docker", info.DockerVersion})
		}
		if info.Uptime != "" {
			pairs = append(pairs, KV{"Uptime", formatUptime(info.Uptime)})
		}
		if info.LoadAverage != "" {
			pairs = append(pairs, KV{"Load", formatLoadAvg(info.LoadAverage, false)})
		}
	}
	if len(r.Metadata.Services) > 0 {
		if len(r.Metadata.Services) == 1 {
			pairs = append(pairs, KV{"Service", r.Metadata.Services[0].Name})
		} else {
			names := make([]string, len(r.Metadata.Services))
			for i, s := range r.Metadata.Services {
				names[i] = s.Name
			}
			pairs = append(pairs, KV{"Services", fmt.Sprintf("%d (%s)", len(r.Metadata.Services), strings.Join(names, ", "))})
		}
	}
	if r.Metadata.ComposeFile != "" {
		pairs = append(pairs, KV{"Compose", truncatePathForWidth(r.Metadata.ComposeFile, outerW-16)})
	}
	if len(r.Metadata.Adapters) > 0 {
		names := make([]string, len(r.Metadata.Adapters))
		for i, a := range r.Metadata.Adapters {
			names[i] = a.Name
		}
		pairs = append(pairs, KV{"Adapters", strings.Join(names, ", ")})
	}
	body := renderKV(pairs, 12)
	if body == "" {
		body = "  No scan context available"
	}
	return body
}

func renderOverviewRow(r *domain.ScanResult, theme Theme, width int) string {
	if width < 80 {
		leftContent := scanContextContent(r, theme, width)
		lines := strings.Count(leftContent, "\n") + 1
		leftH := clamp(lines+3, 4, 12)
		left := renderCardBounded("Scan context", leftContent, theme, Rect{W: width, H: leftH})

		rightContent := scoreBarContent(r, theme, width)
		rlines := strings.Count(rightContent, "\n") + 1
		rightH := clamp(rlines+3, 4, 12)
		right := renderCardBounded("Area health", rightContent, theme, Rect{W: width, H: rightH})
		return joinRowsWithGap(0, left, right)
	}

	colW := (width - 1) / 2
	rightW := width - colW - 1

	leftContent := scanContextContent(r, theme, colW)
	rightContent := scoreBarContent(r, theme, rightW)

	leftLines := strings.Count(leftContent, "\n") + 1
	rightLines := strings.Count(rightContent, "\n") + 1
	cardH := clamp(max(leftLines, rightLines)+3, 4, 12)

	left := renderCardBounded("Scan context", leftContent, theme, Rect{W: colW, H: cardH})
	right := renderCardBounded("Area health", rightContent, theme, Rect{W: rightW, H: cardH})

	leftSplit := strings.Split(left, "\n")
	rightSplit := strings.Split(right, "\n")
	maxH := max(len(leftSplit), len(rightSplit))
	for len(leftSplit) < maxH {
		leftSplit = append(leftSplit, strings.Repeat(" ", colW))
	}
	for len(rightSplit) < maxH {
		rightSplit = append(rightSplit, strings.Repeat(" ", rightW))
	}
	var result []string
	for i := 0; i < maxH; i++ {
		result = append(result, leftSplit[i]+" "+rightSplit[i])
	}
	body := strings.Join(result, "\n")
	if debugLayout {
		assertDisplayWidthLTE(body, width)
	}
	return body
}

func truncateStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}
