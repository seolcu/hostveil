package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

type historyModel struct {
	scroll         int
	exportCursor   int
	lastExportPath string
}

type exportFormatItem struct {
	name string
	desc string
}

var reportExportFormats = []exportFormatItem{
	{"json", "Machine-readable output"},
	{"sarif", "GitHub code scanning / security tools"},
	{"markdown", "Human-readable report"},
	{"html", "Shareable dashboard"},
}

func (m *historyModel) Update(msg tea.Msg) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		s := msg.String()
		switch s {
		case "j", "down":
			m.exportCursor++
			if m.exportCursor >= len(reportExportFormats) {
				m.exportCursor = 0
			}
		case "k", "up":
			m.exportCursor--
			if m.exportCursor < 0 {
				m.exportCursor = len(reportExportFormats) - 1
			}
		case "r":
			m.exportCursor = 0
		}
	}
}

func (m *historyModel) render(r *domain.ScanResult, theme Theme, width, height int) string {
	if width < 20 {
		return "Terminal too narrow"
	}

	if width < miniWidth {
		return m.renderMiniReport(r, theme, width)
	}

	lm := layoutMode(width, height)
	if lm == LayoutUltraWide {
		return m.renderUltraWideReport(r, theme, width, height)
	}
	if lm == LayoutWide {
		return m.renderWideReport(r, theme, width, height)
	}
	if lm == LayoutCompact {
		return m.renderCompactReport(r, theme, width)
	}

	return m.renderMediumReport(r, theme, width, height)
}

// ─── Report Shared Layout ─────────────────────────────────────────────────

func (m *historyModel) renderGridReport(r *domain.ScanResult, theme Theme, width, height int, mode LayoutMode) string {
	slots := ReportSlots(width, height, mode)
	sp := spacingFor(mode)

	summary := m.renderCurrentScanSummaryCard(r, theme, slots.Row1[0].W, slots.Row1[0].H)
	export := m.renderExportCard(r, theme, slots.Row1[1].W, slots.Row1[1].H)
	row1w := []int{slots.Row1[0].W, slots.Row1[1].W}
	row1 := joinColumns([]string{summary, export}, row1w, sp.ColGap)

	areaHealth := m.renderAreaHealthCardReport(r, theme, slots.Row2[0].W, slots.Row2[0].H)
	scanCov := m.renderScanCoverageCardReport(r, theme, slots.Row2[1].W, slots.Row2[1].H)
	row2w := []int{slots.Row2[0].W, slots.Row2[1].W}
	row2 := joinColumns([]string{areaHealth, scanCov}, row2w, sp.ColGap)

	notes := m.renderNotesWarningsCard(r, theme, slots.Row3[0].W, slots.Row3[0].H)
	contents := m.renderReportContentsCard(r, theme, slots.Row3[1].W, slots.Row3[1].H)
	row3w := []int{slots.Row3[0].W, slots.Row3[1].W}
	row3 := joinColumns([]string{notes, contents}, row3w, sp.ColGap)

	guidance := renderInfoStrip("Export guidance",
		"JSON for automation · SARIF for code/security tooling · Markdown for project docs · HTML for sharing with non-technical reviewers",
		theme, slots.Guidance.W, slots.Guidance.H)

	rootW := slots.Row1[0].W + slots.Row1[1].W + sp.ColGap
	if debugLayout {
		assertDisplayWidthLTE(row1, rootW)
		assertDisplayWidthLTE(row2, rootW)
		assertDisplayWidthLTE(row3, rootW)
	}

	return joinRowsWithGap(sp.RowGap, row1, row2, row3, guidance)
}

func (m *historyModel) renderUltraWideReport(r *domain.ScanResult, theme Theme, width, height int) string {
	return m.renderGridReport(r, theme, width, height, LayoutUltraWide)
}

func (m *historyModel) renderCurrentScanSummaryCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	pairs := []KV{
		{"Score", fmt.Sprintf("%d/100", r.ScoreReport.Overall)},
		{"Risk", r.ScoreReport.Grade()},
		{"Findings", fmt.Sprintf("%d", r.TotalFindings())},
		{"Services", fmt.Sprintf("%d", len(r.Metadata.Services))},
	}
	info := r.Metadata.HostRuntime
	if info != nil {
		if info.Hostname != "" {
			pairs = append(pairs, KV{"Hostname", info.Hostname})
		}
		if info.DockerVersion != "" {
			pairs = append(pairs, KV{"Docker", info.DockerVersion})
		}
	}
	modeStr := "live"
	if r.Metadata.ScanMode == domain.ScanModeExplicit {
		modeStr = "explicit"
	}
	pairs = append(pairs, KV{"Scan mode", modeStr})
	return renderCardBounded("Current scan summary", renderKV(pairs, 16), theme, Rect{W: outerW, H: height})
}

func (m *historyModel) renderExportCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var lines []string
	for i, ef := range reportExportFormats {
		cursor := " "
		if i == m.exportCursor {
			cursor = "❯"
		}
		formatName := strings.ToUpper(ef.name[:1]) + ef.name[1:]
		nameStr := lipgloss.NewStyle().
			Bold(i == m.exportCursor).
			Foreground(lipgloss.Color(theme.TextBright)).
			Render(formatName)
		descStr := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(ef.desc)
		lines = append(lines, fmt.Sprintf("  %s %s  %s", cursor, nameStr, descStr))
	}
	lines = append(lines, "")
	if m.lastExportPath != "" {
		pathLabel := truncatePathForWidth(m.lastExportPath, outerW-16)
		lines = append(lines, fmt.Sprintf("  Last export: %s", pathLabel))
	} else {
		pathLabel := truncatePathForWidth("./hostveil_report_YYYYMMDD_HHMMSS.<format>", outerW-16)
		lines = append(lines, fmt.Sprintf("  Output path: %s", pathLabel))
	}
	lines = append(lines, "")
	lines = append(lines, "  "+lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("j/k select · Enter export"))
	return renderCardBounded("Export report", strings.Join(lines, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *historyModel) renderAreaHealthCardReport(r *domain.ScanResult, theme Theme, outerW, height int) string {
	lm := LayoutUltraWide
	if outerW < 120 {
		lm = LayoutWide
	}
	return renderCardBounded("Area health", strings.Join(renderAreaHealthBars(r, outerW, lm, theme), "\n"), theme, Rect{W: outerW, H: height})
}

func (m *historyModel) renderScanCoverageCardReport(r *domain.ScanResult, theme Theme, outerW, height int) string {
	svcCount := fmt.Sprintf("%d", len(r.Metadata.Services))
	if len(r.Metadata.Services) == 0 {
		svcCount = "none"
	}
	comp := truncatePathForWidth(r.Metadata.ComposeFile, outerW-24)
	if r.Metadata.ComposeFile == "" {
		comp = "not found"
	}
	pairs := []KV{
		{"Compose services", svcCount},
		{"Compose file", comp},
		{"Host checks", "enabled"},
		{"Image checks", "available"},
		{"Secret checks", "available"},
	}
	return renderCardBounded("Scan coverage", renderKV(pairs, 18), theme, Rect{W: outerW, H: height})
}

func (m *historyModel) renderNotesWarningsCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var lines []string
	if len(r.Metadata.Adapters) > 0 {
		for _, a := range r.Metadata.Adapters {
			lines = append(lines, fmt.Sprintf("  ℹ Adapter detected: %s", a.Name))
		}
	} else {
		lines = append(lines, "  ℹ No adapters detected.")
	}
	if len(r.Metadata.Warnings) > 0 {
		for _, w := range r.Metadata.Warnings {
			lines = append(lines, fmt.Sprintf("  ⚠ %s", w))
		}
	} else {
		lines = append(lines, "  No warnings emitted.")
	}
	return renderCardBounded("Notes and warnings", strings.Join(lines, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *historyModel) renderReportContentsCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	baseItems := []string{
		"• Overall score and risk grade",
		"• Findings summary",
		"• Area health / risk by area",
		"• Runtime and adapter metadata",
		"• Export timestamp",
	}

	var extraItems []string
	if r.TotalFindings() == 0 {
		extraItems = []string{
			"• Clean scan statement",
			"• Scan coverage limitations",
		}
	} else {
		extraItems = []string{
			"• Finding details and remediation guidance",
			"• Fix preview metadata where available",
		}
	}

	items := append(baseItems, extraItems...)
	return renderCardBounded("Report contents", "  "+strings.Join(items, "\n  "), theme, Rect{W: outerW, H: height})
}

// ─── Wide Report (≥120x35) ──────────────────────────────────────────────────

func (m *historyModel) renderWideReport(r *domain.ScanResult, theme Theme, width, height int) string {
	return m.renderGridReport(r, theme, width, height, LayoutWide)
}

// ─── Medium Report (default) ────────────────────────────────────────────────

func (m *historyModel) renderMediumReport(r *domain.ScanResult, theme Theme, width, height int) string {
	sp := spacingFor(LayoutMedium)
	contentW := width - sp.OuterX*2 - 2 - sp.CardPadX*2

	// Height budget per card: divide available height evenly among stacked cards
	// (summary, severity, export = 3 always; info = 4th if present)
	nCards := 4
	hasInfo := len(r.Metadata.InfoMessages) > 0 || len(r.Metadata.Warnings) > 0
	if !hasInfo {
		nCards = 3
	}
	gapH := max(0, sp.RowGap)
	usableH := height - gapH*(nCards-1)
	if usableH < nCards*3 {
		usableH = height
		gapH = 0
	}
	cardH := usableH / nCards

	// Card 1: Current scan summary
	var axisRows []string
	info := fmt.Sprintf("Score: %d (%s)  |  Findings: %d  |  Services: %d",
		r.ScoreReport.Overall, r.ScoreReport.Grade(),
		r.TotalFindings(), len(r.Metadata.Services))
	axisRows = append(axisRows, info)
	axisRows = append(axisRows, "")

	axisRows = append(axisRows,
		lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).Render("  Area health"))
	axisRows = append(axisRows, "")

	areaBars := renderAreaHealthBars(r, contentW, LayoutMedium, theme)
	axisRows = append(axisRows, areaBars...)

	card1 := renderCardBounded("Current scan summary", strings.Join(axisRows, "\n"), theme, Rect{W: width, H: cardH})

	// Card 2: Severity summary
	var sevRows []string
	sevParts := []string{}
	for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		count := r.FindingsBySeverity(sev)
		if count > 0 {
			col := sev.Color()
			sevParts = append(sevParts,
				lipgloss.NewStyle().Foreground(lipgloss.Color(col)).Render(fmt.Sprintf("%s: %d", sev.String(), count)),
			)
		}
	}
	if len(sevParts) > 0 {
		sevRows = append(sevRows, "  "+strings.Join(sevParts, "  "))
	} else {
		sevRows = append(sevRows,
			"  "+lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Success)).Render("No severity findings"))
	}
	card2 := renderCardBounded("", strings.Join(sevRows, "\n"), theme, Rect{W: width, H: cardH})

	// Card 3: Export options (selectable)
	var exportRows []string

	for i, ef := range reportExportFormats {
		cursor := " "
		if i == m.exportCursor {
			cursor = ">"
		}
		formatName := strings.ToUpper(ef.name[:1]) + ef.name[1:]
		nameStr := lipgloss.NewStyle().
			Bold(i == m.exportCursor).
			Foreground(lipgloss.Color(theme.TextBright)).
			Render(formatName)
		descStr := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(ef.desc)
		exportRows = append(exportRows, fmt.Sprintf("  %s %s  %s", cursor, nameStr, descStr))
	}
	exportRows = append(exportRows, "")
	exportRows = append(exportRows, "  "+lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Enter export · j/k select · s settings"))
	card3 := renderCardBounded("Export report", strings.Join(exportRows, "\n"), theme, Rect{W: width, H: cardH})

	// Card 4: Info messages and warnings
	infoLines := []string{}
	if len(r.Metadata.InfoMessages) > 0 {
		var projects []string
		var otherMsgs []string
		seenProjects := make(map[string]bool)
		for _, msg := range r.Metadata.InfoMessages {
			trimmed := strings.TrimPrefix(msg, "Discovered project: ")
			if trimmed != msg {
				parts := strings.SplitN(trimmed, " at ", 2)
				if len(parts) >= 1 && parts[0] != "" {
					if !seenProjects[parts[0]] {
						projects = append(projects, parts[0])
						seenProjects[parts[0]] = true
					}
				}
			} else {
				otherMsgs = append(otherMsgs, msg)
			}
		}
		if len(projects) > 0 {
			infoLines = append(infoLines, fmt.Sprintf("  ℹ Discovered %d project(s): %s", len(projects), strings.Join(projects, ", ")))
		}
		for _, msg := range otherMsgs {
			infoLines = append(infoLines, fmt.Sprintf("  ℹ %s", msg))
		}
	}
	if len(r.Metadata.Warnings) > 0 {
		for _, w := range r.Metadata.Warnings {
			infoLines = append(infoLines, fmt.Sprintf("  ⚠ %s", w))
		}
	}
	card4 := ""
	if len(infoLines) > 0 {
		card4 = renderCardBounded("", strings.Join(infoLines, "\n"), theme, Rect{W: width, H: cardH})
	}

	cards := []string{card1, card2, card3}
	if card4 != "" {
		cards = append(cards, card4)
	}
	content := joinRowsWithGap(gapH, cards...)

	style := lipgloss.NewStyle().
		Width(width).
		Padding(sp.OuterY, sp.OuterX)

	return style.Render(content)
}

func (m *historyModel) renderMiniReport(r *domain.ScanResult, theme Theme, width int) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	findings := r.TotalFindings()

	gradeColor := theme.GradeColor(score)

	line1 := lipgloss.NewStyle().Bold(true).Render("Report")
	scoreStr := lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score %d/%d", score, 100))
	gradeStr := lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(grade)
	line2 := fmt.Sprintf("%s · %s", scoreStr, gradeStr)

	var lines []string
	lines = append(lines, line1, line2)

	if findings > 0 {
		lines = append(lines, fmt.Sprintf("%d findings", findings))
		// Severity summary
		var sevParts []string
		for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
			count := r.FindingsBySeverity(sev)
			if count > 0 {
				sevParts = append(sevParts,
					lipgloss.NewStyle().Foreground(lipgloss.Color(sev.Color())).Render(fmt.Sprintf("%s: %d", strings.ToUpper(sev.String()), count)),
				)
			}
		}
		if len(sevParts) > 0 {
			lines = append(lines, strings.Join(sevParts, "  "))
		}
	}

	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Enter export · j/k select · q quit"))

	style := lipgloss.NewStyle().Width(width).Padding(0, 1)
	return style.Render(strings.Join(lines, "\n"))
}

// ─── Compact Report (50-79px) ──────────────────────────────────────────────

func (m *historyModel) renderCompactReport(r *domain.ScanResult, theme Theme, width int) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	findings := r.TotalFindings()

	gradeColor := theme.GradeColor(score)

	line1 := lipgloss.NewStyle().Bold(true).Render("Report")
	scoreStr := lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score %d/%d", score, 100))
	gradeStr := lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(grade)
	line2 := fmt.Sprintf("%s · %s · %d findings", scoreStr, gradeStr, findings)

	var lines []string
	lines = append(lines, line1, line2, "")

	for i, ef := range reportExportFormats {
		cursor := " "
		if i == m.exportCursor {
			cursor = ">"
		}
		nameStr := lipgloss.NewStyle().
			Bold(i == m.exportCursor).
			Foreground(lipgloss.Color(theme.TextBright)).
			Render(strings.ToUpper(ef.name[:1]) + ef.name[1:])
		descStr := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(ef.desc)
		lines = append(lines, fmt.Sprintf("%s %s  %s", cursor, nameStr, descStr))
	}
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Enter export · j/k select · q quit"))

	style := lipgloss.NewStyle().Width(width).Padding(0, 1)
	return style.Render(strings.Join(lines, "\n"))
}
