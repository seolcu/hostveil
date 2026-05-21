package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

type historyModel struct {
	scroll           int
	exportCursor     int
	lastExportPath   string
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
		return m.renderUltraWideReport(r, theme, width)
	}
	if lm == LayoutWide {
		return m.renderWideReport(r, theme, width)
	}

	return m.renderMediumReport(r, theme, width)
}

// ─── UltraWide Report (≥180x45) ─────────────────────────────────────────────

func (m *historyModel) renderUltraWideReport(r *domain.ScanResult, theme Theme, width int) string {
	sp := spacingFor(LayoutUltraWide)
	rootW := width - sp.OuterX*2
	cols := splitColumns(rootW, 2, sp.ColGap)

	summary := m.renderCurrentScanSummaryCard(r, theme, cols[0])
	export := m.renderExportCard(r, theme, cols[1])
	row1 := joinColumns([]string{summary, export}, cols, sp.ColGap)

	areaHealth := m.renderAreaHealthCardReport(r, theme, cols[0])
	scanCov := m.renderScanCoverageCardReport(r, theme, cols[1])
	row2 := joinColumns([]string{areaHealth, scanCov}, cols, sp.ColGap)

	notes := m.renderNotesWarningsCard(r, theme, cols[0])
	contents := m.renderReportContentsCard(r, theme, cols[1])
	row3 := joinColumns([]string{notes, contents}, cols, sp.ColGap)

	guidance := m.renderExportGuidanceCard(theme, rootW)

	rowGap := "\n" + strings.Repeat("\n", sp.RowGap)
	return row1 + rowGap + row2 + rowGap + row3 + rowGap + guidance
}

func (m *historyModel) renderCurrentScanSummaryCard(r *domain.ScanResult, theme Theme, outerW int) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("  Score           %d/100", r.ScoreReport.Overall))
	lines = append(lines, fmt.Sprintf("  Risk            %s", r.ScoreReport.Grade()))
	lines = append(lines, fmt.Sprintf("  Findings        %d", r.TotalFindings()))
	lines = append(lines, fmt.Sprintf("  Services        %d", len(r.Metadata.Services)))

	info := r.Metadata.HostRuntime
	if info != nil {
		if info.Hostname != "" {
			lines = append(lines, fmt.Sprintf("  Hostname        %s", info.Hostname))
		}
		if info.DockerVersion != "" {
			lines = append(lines, fmt.Sprintf("  Docker          %s", info.DockerVersion))
		}
	}

	modeStr := "live"
	if r.Metadata.ScanMode == domain.ScanModeExplicit {
		modeStr = "explicit"
	}
	lines = append(lines, fmt.Sprintf("  Scan mode       %s", modeStr))

	return renderCardBounded("Current scan summary", strings.Join(lines, "\n"), theme, Rect{W: outerW})
}

func (m *historyModel) renderExportCard(r *domain.ScanResult, theme Theme, outerW int) string {
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
	return renderCardBounded("Export report", strings.Join(lines, "\n"), theme, Rect{W: outerW})
}

func (m *historyModel) renderAreaHealthCardReport(r *domain.ScanResult, theme Theme, outerW int) string {
	lm := LayoutUltraWide
	if outerW < 120 {
		lm = LayoutWide
	}
	return renderCardBounded("Area health", strings.Join(renderAreaHealthBars(r, outerW, lm, theme), "\n"), theme, Rect{W: outerW})
}

func (m *historyModel) renderScanCoverageCardReport(r *domain.ScanResult, theme Theme, outerW int) string {
	var lines []string
	addLine := func(k, v string) {
		lines = append(lines, fmt.Sprintf("  %-20s %s", k+":", v))
	}

	if len(r.Metadata.Services) > 0 {
		addLine("Compose services", fmt.Sprintf("%d", len(r.Metadata.Services)))
	} else {
		addLine("Compose services", "none")
	}
	if r.Metadata.ComposeFile != "" {
		addLine("Compose file", truncatePathForWidth(r.Metadata.ComposeFile, outerW-24))
	} else {
		addLine("Compose file", "not found")
	}
	addLine("Host checks", "enabled")
	addLine("Image checks", "available")
	addLine("Secret checks", "available")

	return renderCardBounded("Scan coverage", strings.Join(lines, "\n"), theme, Rect{W: outerW})
}

func (m *historyModel) renderNotesWarningsCard(r *domain.ScanResult, theme Theme, outerW int) string {
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
	return renderCardBounded("Notes and warnings", strings.Join(lines, "\n"), theme, Rect{W: outerW})
}

func (m *historyModel) renderReportContentsCard(r *domain.ScanResult, theme Theme, outerW int) string {
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
	return renderCardBounded("Report contents", "  "+strings.Join(items, "\n  "), theme, Rect{W: outerW})
}

func (m *historyModel) renderExportGuidanceCard(theme Theme, outerW int) string {
	text := "JSON for automation · SARIF for code/security tooling · Markdown for project docs · HTML for sharing with non-technical reviewers"
	return renderCardBounded("Export guidance", "  "+text, theme, Rect{W: outerW})
}

// ─── Wide Report (≥120x35) ──────────────────────────────────────────────────

func (m *historyModel) renderWideReport(r *domain.ScanResult, theme Theme, width int) string {
	sp := spacingFor(LayoutWide)
	rootW := width - sp.OuterX*2
	cols := splitColumns(rootW, 2, sp.ColGap)

	summary := m.renderCurrentScanSummaryCard(r, theme, cols[0])
	export := m.renderExportCard(r, theme, cols[1])
	row1 := joinColumns([]string{summary, export}, cols, sp.ColGap)

	areaHealth := m.renderAreaHealthCardReport(r, theme, cols[0])
	scanCov := m.renderScanCoverageCardReport(r, theme, cols[1])
	row2 := joinColumns([]string{areaHealth, scanCov}, cols, sp.ColGap)

	notes := m.renderNotesWarningsCard(r, theme, cols[0])
	contents := m.renderReportContentsCard(r, theme, cols[1])
	row3 := joinColumns([]string{notes, contents}, cols, sp.ColGap)

	guidance := m.renderExportGuidanceCard(theme, rootW)

	rowGap := "\n" + strings.Repeat("\n", sp.RowGap)
	return row1 + rowGap + row2 + rowGap + row3 + rowGap + guidance
}

// ─── Medium Report (default) ────────────────────────────────────────────────

func (m *historyModel) renderMediumReport(r *domain.ScanResult, theme Theme, width int) string {
	sp := spacingFor(LayoutMedium)
	contentW := width - sp.OuterX*2 - 2 - sp.CardPadX*2

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

	card1 := renderCardBounded("Current scan summary", strings.Join(axisRows, "\n"), theme, Rect{W: width})

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
	card2 := renderCardBounded("", strings.Join(sevRows, "\n"), theme, Rect{W: width})

	// Card 3: Export options (selectable)
	var exportRows []string
	exportTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Accent)).Render("Export report")
	exportRows = append(exportRows, exportTitle)
	exportRows = append(exportRows, "")

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
	card3 := renderCardBounded("Export report", strings.Join(exportRows, "\n"), theme, Rect{W: width})

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
		card4 = renderCardBounded("", strings.Join(infoLines, "\n"), theme, Rect{W: width})
	}

	rowGap := "\n" + strings.Repeat("\n", sp.RowGap)
	content := card1 + rowGap + card2 + rowGap + card3
	if card4 != "" {
		content += rowGap + card4
	}

	style := lipgloss.NewStyle().
		Width(width).
		Padding(sp.OuterY, sp.OuterX)

	return style.Render(content)
}

func (m *historyModel) renderMiniReport(r *domain.ScanResult, theme Theme, width int) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	findings := r.TotalFindings()

	gradeColor := theme.Critical
	if score >= 50 {
		gradeColor = theme.Medium
	}
	if score >= 80 {
		gradeColor = theme.Success
	}

	line1 := lipgloss.NewStyle().Bold(true).Render("Report")
	line2 := lipgloss.JoinHorizontal(lipgloss.Center,
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score %d/%d", score, 100)),
		" · ",
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(grade),
	)

	var line3 string
	if findings == 0 {
		line3 = "Enter export · s settings"
	} else {
		line3 = fmt.Sprintf("%d findings · Enter export · s settings", findings)
	}

	style := lipgloss.NewStyle().Width(width).Padding(0, 1)
	return style.Render(line1 + "\n" + line2 + "\n" + line3)
}
