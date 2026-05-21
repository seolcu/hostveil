package tui

import (
	"fmt"
	"sort"
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

	lm := layoutMode(width, height)

	if lm == LayoutMini || width < miniWidth {
		return m.renderMiniDashboard(r, theme, width)
	}

	state := DashboardClean
	if r.TotalFindings() > 0 {
		state = DashboardRisk
	}

	switch lm {
	case LayoutUltraWide:
		return m.renderUltraWideDashboard(r, theme, width, height, state)
	case LayoutWide:
		return m.renderWideDashboard(r, theme, width, height, state)
	default:
		return m.renderMediumDashboard(r, theme, width, height, state)
	}
}

// ─── Medium Dashboard (default) ─────────────────────────────────────────────

func (m *overviewModel) renderMediumDashboard(r *domain.ScanResult, theme Theme, width, height int, state DashboardState) string {
	slots := DashboardSlots(width, height, state, LayoutMedium)

	var hero string
	if state == DashboardClean {
		hero = m.renderAllClearHeroCard(theme, width, slots.Hero.InnerH())
	} else {
		hero = m.renderRiskSummaryHeroCard(r, theme, width, slots.Hero.InnerH())
	}

	// Main row: 2 columns or stacked
	var mainContent string
	colW := slots.Row1[0].W
	if len(slots.Row1) >= 2 && width >= mediumWidth {
		col2w := []int{slots.Row1[0].W, slots.Row1[1].W}
		if state == DashboardClean {
			row1 := []string{
				m.renderAreaHealthCardScore(r, theme, slots.Row1[0].InnerW(), slots.Row1[0].InnerH(), LayoutMedium),
				m.renderScanCoverageCard(r, theme, slots.Row1[1].InnerW(), slots.Row1[1].InnerH()),
			}
			mainContent = joinColumns(row1, col2w, 2)
		} else {
			row1 := []string{
				m.renderNextActionsCard(r, theme, slots.Row1[0].InnerW(), slots.Row1[0].InnerH()),
				m.renderRiskByAreaCard(r, theme, slots.Row1[1].InnerW(), slots.Row1[1].InnerH()),
			}
			mainContent = joinColumns(row1, col2w, 2)
		}
	} else {
		if state == DashboardClean {
			mainContent = m.renderAreaHealthCardScore(r, theme, colW, slots.Row1[0].InnerH(), LayoutMedium) + "\n\n" +
				m.renderScanCoverageCard(r, theme, colW, slots.Row1[0].InnerH())
		} else {
			mainContent = m.renderNextActionsCard(r, theme, colW, slots.Row1[0].InnerH()) + "\n\n" +
				m.renderRiskByAreaCard(r, theme, colW, slots.Row1[0].InnerH())
		}
	}

	var timeline string
	if state == DashboardClean {
		timeline = m.renderWorkflowTimelineCardClean(theme, width, slots.Timeline.InnerH())
	} else {
		timeline = m.renderWorkflowTimelineCardRisk(theme, width, slots.Timeline.InnerH())
	}

	return joinRows(
		hero,
		"",
		mainContent,
		"",
		timeline,
	)
}

func (m *overviewModel) renderAllClearCard(theme Theme, outerW, height int) string {
	icon := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Success)).
		Bold(true).
		Render("✓ All clear")

	msg := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("No findings detected in enabled checks.\nYour current scan passed the checks that actually ran.")

	return renderCardBounded("", icon+"\n"+msg, theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderScanCoverageCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("  %-12s %s", k+":", v))
	}

	if len(r.Metadata.Services) > 0 {
		addRow("Services", fmt.Sprintf("%d", len(r.Metadata.Services)))
	} else {
		addRow("Services", "none")
	}
	if r.Metadata.ComposeFile != "" {
		addRow("Compose", truncatePathForWidth(r.Metadata.ComposeFile, outerW-16))
	}

	if len(rows) == 1 {
		rows = append(rows, "")
	}

	return renderCardBounded("Scan coverage", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderRuntimeAdaptersCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("  %-12s %s", k+":", v))
	}

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
			addRow("Load", formatLoadAvg(info.LoadAverage, false))
		}
	}
	if len(r.Metadata.Adapters) > 0 {
		names := make([]string, len(r.Metadata.Adapters))
		for i, a := range r.Metadata.Adapters {
			names[i] = a.Name
		}
		addRow("Adapters", strings.Join(names, ", "))
	}

	if len(rows) == 0 {
		rows = append(rows, "  No runtime data")
	}

	return renderCardBounded("Runtime / adapters", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderNextStepsCard(theme Theme, outerW, height int) string {
	steps := []string{
		"  • Press 3 to export a clean report.",
		"  • Place a docker-compose.yml file in the current directory for service scanning.",
		"  • Rescan after adding or changing services.",
		"  • Review Host Hardening recommendations even in clean scans.",
	}
	return renderCardBounded("Next steps", strings.Join(steps, "\n"), theme, Rect{W: outerW, H: height})
}

// ─── UltraWide Dashboard (≥180x45) ───────────────────────────────────────────

func (m *overviewModel) renderUltraWideDashboard(r *domain.ScanResult, theme Theme, width, height int, state DashboardState) string {
	slots := DashboardSlots(width, height, state, LayoutUltraWide)

	var statusLine string
	if state == DashboardClean {
		statusLine = m.renderStatusLineClean(r, theme)
	} else {
		statusLine = m.renderStatusLineRisk(r, theme)
	}

	var hero string
	if state == DashboardClean {
		hero = m.renderAllClearHeroCard(theme, width, slots.Hero.InnerH())
	} else {
		hero = m.renderRiskSummaryHeroCard(r, theme, width, slots.Hero.InnerH())
	}

	// Row1: 4 columns
	col4w := make([]int, len(slots.Row1))
	var col4Cards []string
	for i := range slots.Row1 {
		col4w[i] = slots.Row1[i].W
	}
	if state == DashboardClean {
		col4Cards = []string{
			m.renderScanCoverageCard(r, theme, slots.Row1[0].InnerW(), slots.Row1[0].InnerH()),
			m.renderAreaHealthCardScore(r, theme, slots.Row1[1].InnerW(), slots.Row1[1].InnerH(), LayoutUltraWide),
			m.renderRuntimeCard(r, theme, slots.Row1[2].InnerW(), slots.Row1[2].InnerH()),
			m.renderAdaptersCard(r, theme, slots.Row1[3].InnerW(), slots.Row1[3].InnerH()),
		}
	} else {
		col4Cards = []string{
			m.renderNextActionsCard(r, theme, slots.Row1[0].InnerW(), slots.Row1[0].InnerH()),
			m.renderRiskByAreaCardFindings(r, theme, slots.Row1[1].InnerW(), slots.Row1[1].InnerH()),
			m.renderAffectedServicesCard(r, theme, slots.Row1[2].InnerW(), slots.Row1[2].InnerH()),
			m.renderFixQueueCard(r, theme, slots.Row1[3].InnerW(), slots.Row1[3].InnerH()),
		}
	}
	grid4 := joinColumns(col4Cards, col4w, 2)

	// Row2 + Row3: 2 columns each
	col2w := []int{slots.Row2[0].W, slots.Row2[1].W}
	var grid2a, grid2b string
	if state == DashboardClean {
		row2clean := []string{
			m.renderRecommendedNextStepsCard(r, theme, slots.Row2[0].InnerW(), slots.Row2[0].InnerH()),
			m.renderWhatThisResultMeansCard(r, theme, slots.Row2[1].InnerW(), slots.Row2[1].InnerH()),
		}
		grid2a = joinColumns(row2clean, col2w, 2)

		row3clean := []string{
			m.renderReportPreviewCard(theme, slots.Row3[0].InnerW(), slots.Row3[0].InnerH()),
			m.renderRecentScanNotesCard(r, theme, slots.Row3[1].InnerW(), slots.Row3[1].InnerH()),
		}
		grid2b = joinColumns(row3clean, col2w, 2)
	} else {
		row2risk := []string{
			m.renderRiskWorkflowCard(r, theme, slots.Row2[0].InnerW(), slots.Row2[0].InnerH()),
			m.renderWhyScoreLowCard(r, theme, slots.Row2[1].InnerW(), slots.Row2[1].InnerH()),
		}
		grid2a = joinColumns(row2risk, col2w, 2)

		row3risk := []string{
			m.renderSelectedPreviewCard(r, theme, slots.Row3[0].InnerW(), slots.Row3[0].InnerH()),
			m.renderScanContextCard(r, theme, slots.Row3[1].InnerW(), slots.Row3[1].InnerH()),
		}
		grid2b = joinColumns(row3risk, col2w, 2)
	}

	var timeline string
	if state == DashboardClean {
		timeline = m.renderWorkflowTimelineCardClean(theme, width, slots.Timeline.InnerH())
	} else {
		timeline = m.renderWorkflowTimelineCardRisk(theme, width, slots.Timeline.InnerH())
	}

	return joinRows(
		statusLine,
		hero,
		"",
		grid4,
		"",
		grid2a,
		"",
		grid2b,
		"",
		timeline,
	)
}

func (m *overviewModel) renderStatusLineClean(r *domain.ScanResult, theme Theme) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	gradeColor := theme.Success
	if score < 80 {
		gradeColor = theme.Medium
	}
	scoreStr := lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score: %d/100 · Risk: %s", score, grade))
	findings := r.TotalFindings()
	svcs := len(r.Metadata.Services)
	return fmt.Sprintf("  %s · %d findings · %d services · %d auto-fixable",
		scoreStr, findings, svcs, 0)
}

func (m *overviewModel) renderAllClearHeroCard(theme Theme, outerW, height int) string {
	icon := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Success)).
		Bold(true).
		Render("✓ All clear")

	msg := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Text)).
		Render("No findings detected in enabled checks.\nYour current scan passed the checks that actually ran.")

	interp := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("Interpretation\nNo Compose services were discovered, so service-level checks were limited.\nAdd docker-compose.yml to evaluate public bindings, privileges, and filesystem risks.")

	body := icon + "\n" + msg + "\n\n" + interp
	return renderCardBounded("", body, theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderAreaHealthCardScore(r *domain.ScanResult, theme Theme, width, height int, mode LayoutMode) string {
	return renderCardBounded("Area health", strings.Join(renderAreaHealthBars(r, width, mode, theme), "\n"), theme, Rect{W: width, H: height})
}

func (m *overviewModel) renderRuntimeCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("%-12s %s", k+":", v))
	}
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
			addRow("Load", formatLoadAvg(info.LoadAverage, false))
		}
	}
	return renderCardBounded("Runtime", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderAdaptersCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var rows []string
	if len(r.Metadata.Adapters) > 0 {
		for _, a := range r.Metadata.Adapters {
			status := "detected"
			rows = append(rows, fmt.Sprintf("  %-12s %s", a.Name+":", status))
		}
	}
	rows = append(rows, "  Missing        none")
	return renderCardBounded("Adapters", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderRecommendedNextStepsCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	steps := []string{
		"1. Add docker-compose.yml to scan service exposure and permissions.",
		"2. Press 3 to export a clean report.",
		"3. Keep host checks enabled after Docker or OS updates.",
		"4. Run again after adding or changing self-hosted services.",
		"5. Review Host Hardening recommendations even in clean scans.",
	}
	var numbered []string
	for _, s := range steps {
		numbered = append(numbered, "  "+s)
	}
	return renderCardBounded("Recommended next steps", strings.Join(numbered, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderWhatThisResultMeansCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	text := `  This is a clean result for the checks that actually ran.
  Because no Compose services were discovered, service-level checks
  (public bindings, container privileges, filesystem risks) were limited.
  Add docker-compose.yml and rescan for full coverage.`
	return renderCardBounded("What this result means", text, theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderReportPreviewCard(theme Theme, outerW, height int) string {
	text := `  Current report status: ready
  Suggested format: Markdown or HTML for sharing

  [3] Report → choose JSON / SARIF / Markdown / HTML`
	return renderCardBounded("Report preview", text, theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderRecentScanNotesCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var lines []string
	for _, a := range r.Metadata.Adapters {
		lines = append(lines, fmt.Sprintf("  ℹ Adapter detected: %s", a.Name))
	}
	if len(r.Metadata.Warnings) > 0 {
		for _, w := range r.Metadata.Warnings {
			lines = append(lines, fmt.Sprintf("  ⚠ %s", w))
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "  No warnings emitted during this scan.")
	}
	return renderCardBounded("Recent scan notes", strings.Join(lines, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderWorkflowTimelineCardClean(theme Theme, outerW, height int) string {
	steps := []string{
		"1 Scan completed ✓",
		"2 Findings analyzed ✓",
		"3 Report ready ○",
		"4 Export report ○",
		"5 Rescan after changes ○",
	}
	line := "  " + strings.Join(steps, "    ")
	return renderCardBounded("Workflow timeline", line, theme, Rect{W: outerW, H: height})
}

// ─── (replaced by renderUltraWideDashboard) ─────────────────────────────────

func (m *overviewModel) renderStatusLineRisk(r *domain.ScanResult, theme Theme) string {
	score := r.ScoreReport.Overall
	grade := r.ScoreReport.Grade()
	gradeColor := theme.Critical
	if score >= 50 {
		gradeColor = theme.Medium
	}
	if score >= 80 {
		gradeColor = theme.Success
	}
	scoreStr := lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score: %d/100 · Risk: %s", score, grade))
	findings := r.TotalFindings()
	svcs := len(r.Metadata.Services)

	autoCount := 0
	for _, f := range r.Findings {
		if f.Remediation == domain.RemediationAuto {
			autoCount++
		}
	}

	return fmt.Sprintf("  %s · %d findings · %d %s · %d auto-fixable",
		scoreStr, findings, svcs, pluralize("service", svcs), autoCount)
}

func (m *overviewModel) renderRiskSummaryHeroCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	grade := r.ScoreReport.Grade()
	score := r.ScoreReport.Overall
	gradeColor := theme.Critical
	if score >= 50 {
		gradeColor = theme.Medium
	}
	if score >= 80 {
		gradeColor = theme.Success
	}

	riskLine := lipgloss.NewStyle().
		Foreground(lipgloss.Color(gradeColor)).
		Bold(true).
		Render(fmt.Sprintf("! %s risk detected. Score: %d/100", grade, score))

	mainIssue := "Main issue: public service exposure."
	var firstHigh *domain.Finding
	for i := range r.Findings {
		if r.Findings[i].Severity == domain.SeverityHigh || r.Findings[i].Severity == domain.SeverityCritical {
			firstHigh = &r.Findings[i]
			if r.Findings[i].Severity == domain.SeverityCritical {
				break
			}
		}
	}
	if firstHigh != nil {
		if firstHigh.Service != "" {
			mainIssue = fmt.Sprintf("Main issue: %s — %s", firstHigh.Service, firstHigh.Title)
		} else {
			mainIssue = fmt.Sprintf("Main issue: %s", firstHigh.Title)
		}
	}

	detail := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Text)).
		Render(mainIssue)

	rec := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Accent)).
		Render("Recommended first move\nOpen Findings, review the two HIGH findings first, preview available fixes, then rescan and export the report.")

	body := riskLine + "\n" + detail + "\n\n" + rec
	return renderCardBounded("Risk summary", body, theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderRiskByAreaCardFindings(r *domain.ScanResult, theme Theme, width, height int) string {
	return m.renderRiskByAreaCard(r, theme, width, height)
}

func (m *overviewModel) renderRiskWorkflowCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	steps := []string{
		"1. Press 2 to open Findings.",
		"2. Select the first HIGH finding.",
		"3. Press p to preview the fix before applying.",
		"4. Apply safe fixes, rescan, then export a report.",
	}
	var numbered []string
	for _, s := range steps {
		numbered = append(numbered, "  "+s)
	}
	return renderCardBounded("Recommended workflow", strings.Join(numbered, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderWhyScoreLowCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	lowestScore := uint8(100)
	lowestAxisName := ""
	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		if score < lowestScore {
			lowestScore = score
			lowestAxisName = axis.Label()
		}
	}
	text := fmt.Sprintf(`  The overall score is mostly reduced by %s.
  Public bindings increase the attack surface, especially for
  user-facing self-hosted services.
  Start with reverse proxy and localhost binding changes.`, lowestAxisName)
	return renderCardBounded("Why the score is low", text, theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderSelectedPreviewCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	if len(r.Findings) == 0 {
		return renderCardBounded("Selected preview", "  No findings to preview.", theme, Rect{W: outerW})
	}

	var firstFixable *domain.Finding
	for i := range r.Findings {
		if r.Findings[i].IsFixable() {
			firstFixable = &r.Findings[i]
			break
		}
	}

	if firstFixable == nil {
		firstFixable = &r.Findings[0]
	}

	f := firstFixable
	sevColor := f.Severity.Color()
	sevStr := strings.ToUpper(f.Severity.String())
	sevTag := lipgloss.NewStyle().
		Foreground(lipgloss.Color(sevColor)).
		Bold(true).
		Render(sevStr)
	remTag := lipgloss.NewStyle().
		Foreground(lipgloss.Color(remediationColor(f.Remediation, theme))).
		Render(f.Remediation.Label())

	var body strings.Builder
	body.WriteString(fmt.Sprintf("  %s · %s\n\n", sevTag, remTag))
	body.WriteString("  " + f.Title + "\n\n")
	if len(f.Evidence) > 0 {
		body.WriteString("  Evidence\n")
		for k, v := range f.Evidence {
			body.WriteString(fmt.Sprintf("    %s: %s\n", k, v))
		}
		body.WriteString("\n")
	}
	body.WriteString("  p preview fix · Enter full detail")

	return renderCardBounded("Selected preview", body.String(), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderWorkflowTimelineCardRisk(theme Theme, width, height int) string {
	steps := []string{
		"1 Scan completed ✓",
		"2 Findings grouped ✓",
		"3 Preview fixes ○",
		"4 Apply / rescan ○",
		"5 Export report ○",
	}
	line := "  " + strings.Join(steps, "    ")
	return renderCardBounded("Workflow timeline", line, theme, Rect{W: width, H: height})
}

// ─── Wide Dashboard (≥120x35) ───────────────────────────────────────────────

func (m *overviewModel) renderWideDashboard(r *domain.ScanResult, theme Theme, width, height int, state DashboardState) string {
	slots := DashboardSlots(width, height, state, LayoutWide)

	var statusLine string
	if state == DashboardClean {
		statusLine = m.renderStatusLineClean(r, theme)
	} else {
		statusLine = m.renderStatusLineRisk(r, theme)
	}

	var hero string
	if state == DashboardClean {
		hero = m.renderAllClearHeroCard(theme, width, slots.Hero.InnerH())
	} else {
		hero = m.renderRiskSummaryHeroCard(r, theme, width, slots.Hero.InnerH())
	}

	// Row1: 3 columns
	col3w := make([]int, len(slots.Row1))
	for i := range slots.Row1 {
		col3w[i] = slots.Row1[i].W
	}
	var mainGrid string
	if state == DashboardClean {
		row1clean := []string{
			m.renderAllClearCard(theme, slots.Row1[0].InnerW(), slots.Row1[0].InnerH()),
			m.renderScanCoverageCard(r, theme, slots.Row1[1].InnerW(), slots.Row1[1].InnerH()),
			m.renderRuntimeAdaptersCard(r, theme, slots.Row1[2].InnerW(), slots.Row1[2].InnerH()),
		}
		mainGrid = joinColumns(row1clean, col3w, 2)
	} else {
		row1risk := []string{
			m.renderNextActionsCard(r, theme, slots.Row1[0].InnerW(), slots.Row1[0].InnerH()),
			m.renderRiskByAreaCard(r, theme, slots.Row1[1].InnerW(), slots.Row1[1].InnerH()),
			m.renderAffectedServicesCard(r, theme, slots.Row1[2].InnerW(), slots.Row1[2].InnerH()),
		}
		mainGrid = joinColumns(row1risk, col3w, 2)
	}

	// Row2: 2 columns
	col2w := []int{slots.Row2[0].W, slots.Row2[1].W}
	var secondaryGrid string
	if state == DashboardClean {
		row2clean := []string{
			m.renderAreaHealthCardScore(r, theme, slots.Row2[0].InnerW(), slots.Row2[0].InnerH(), LayoutWide),
			m.renderNextStepsCard(theme, slots.Row2[1].InnerW(), slots.Row2[1].InnerH()),
		}
		secondaryGrid = joinColumns(row2clean, col2w, 2)
	} else {
		row2risk := []string{
			m.renderFixQueueCard(r, theme, slots.Row2[0].InnerW(), slots.Row2[0].InnerH()),
			m.renderScanContextCard(r, theme, slots.Row2[1].InnerW(), slots.Row2[1].InnerH()),
		}
		secondaryGrid = joinColumns(row2risk, col2w, 2)
	}

	var timeline string
	if state == DashboardClean {
		timeline = m.renderWorkflowTimelineCardClean(theme, width, slots.Timeline.InnerH())
	} else {
		timeline = m.renderWorkflowTimelineCardRisk(theme, width, slots.Timeline.InnerH())
	}

	return joinRows(
		statusLine,
		hero,
		"",
		mainGrid,
		"",
		secondaryGrid,
		"",
		timeline,
	)
}

// ─── Mini dashboard ────────────────────────────────────────────────────────

func (m *overviewModel) renderMiniDashboard(r *domain.ScanResult, theme Theme, width int) string {
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

	line1 := lipgloss.JoinHorizontal(lipgloss.Center,
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(fmt.Sprintf("Score %d/%d", score, 100)),
		" · ",
		lipgloss.NewStyle().Foreground(lipgloss.Color(gradeColor)).Render(grade),
	)

	if findings == 0 {
		line2 := "No findings detected."
		line3 := "3 export · ? help · q quit"
		style := lipgloss.NewStyle().Width(width).Padding(0, 1)
		return style.Render(line1 + "\n" + line2 + "\n" + line3)
	}

	svcCount := len(r.Metadata.Services)
	line2 := fmt.Sprintf("%d findings · %d %s", findings, svcCount, pluralize("service", svcCount))
	line3 := "2 → Findings · ? help · q quit"

	style := lipgloss.NewStyle().Width(width).Padding(0, 1)
	return style.Render(line1 + "\n" + line2 + "\n" + line3)
}

func pluralize(s string, n int) string {
	if n == 1 {
		return s
	}
	return s + "s"
}

func (m *overviewModel) renderNextActionsCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var rows []string

	sorted := make([]domain.Finding, len(r.Findings))
	copy(sorted, r.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity < sorted[j].Severity
		}
		return sorted[i].Remediation < sorted[j].Remediation
	})

	maxActions := 3
	if outerW < 60 {
		maxActions = 2
	}

	count := 0
	for _, f := range sorted {
		if count >= maxActions {
			break
		}
		sevColor := f.Severity.Color()
		icon := severityIcon(f.Severity)
		sevLabel := severityShortLabel(f.Severity)
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
		maxTitle := outerW - len(sevLabel) - len(svc) - 12
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

	return renderCardBounded("Next actions", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderRiskByAreaCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var rows []string

	axisCounts := make(map[domain.Axis]int)
	for _, f := range r.Findings {
		axisCounts[f.Axis]++
	}

	for _, axis := range domain.AllAxes() {
		count := axisCounts[axis]
		labelText := axis.Label()
		if outerW < 45 {
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

		label := lipgloss.NewStyle().Width(22).Render(labelText)

		var countDisplay string
		if count == 0 {
			countDisplay = lipgloss.NewStyle().
				Foreground(lipgloss.Color(theme.Success)).
				Bold(true).
				Render("Clear")
		} else {
			fillColor := theme.Medium
			if count > 3 {
				fillColor = theme.Critical
			}
			findingStr := fmt.Sprintf("%d finding", count)
			if count != 1 {
				findingStr += "s"
			}
			countDisplay = lipgloss.NewStyle().
				Foreground(lipgloss.Color(fillColor)).
				Render(findingStr)
		}
		rows = append(rows, fmt.Sprintf("  %s%s", label, countDisplay))
	}

	return renderCardBounded("Risk by area", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderAffectedServicesCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var rows []string

	type svcInfo struct {
		name        string
		findings    int
		autoFix     int
		reviewFix   int
		manualFix   int
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
		switch f.Remediation {
		case domain.RemediationAuto:
			svcMap[svc].autoFix++
		case domain.RemediationReview:
			svcMap[svc].reviewFix++
		case domain.RemediationManual:
			svcMap[svc].manualFix++
		}
	}

	for _, name := range svcOrder {
		info := svcMap[name]
		svcLabel := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.Accent)).
			Render(name)

		var parts []string
		parts = append(parts, fmt.Sprintf("%d findings", info.findings))

		compact := outerW < 45
		if compact {
			if info.autoFix > 0 {
				parts = append(parts, fmt.Sprintf("%d auto", info.autoFix))
			}
			if info.reviewFix > 0 {
				parts = append(parts, fmt.Sprintf("%d review", info.reviewFix))
			}
		} else {
			if info.autoFix > 0 {
				parts = append(parts, fmt.Sprintf("%d auto-fix", info.autoFix))
			}
			if info.reviewFix > 0 {
				parts = append(parts, fmt.Sprintf("%d review", info.reviewFix))
			}
			if info.manualFix > 0 {
				parts = append(parts, fmt.Sprintf("%d manual", info.manualFix))
			}
		}

		countStr := strings.Join(parts, " · ")
		countLabel := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(countStr)

		inner := outerW - 8
		spacer := inner - lipgloss.Width(stripANSI(svcLabel)) - lipgloss.Width(countStr)
		if spacer < 1 {
			spacer = 1
		}

		rows = append(rows, fmt.Sprintf("  %s%s%s", svcLabel, strings.Repeat(" ", spacer), countLabel))
	}

	if len(rows) == 0 {
		rows = append(rows, "  No services affected")
	}

	return renderCardBounded("Affected services", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
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

func (m *overviewModel) renderFixQueueCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
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

	return renderCardBounded("Fix queue", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
}

func (m *overviewModel) renderScanContextCard(r *domain.ScanResult, theme Theme, outerW, height int) string {
	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("%-12s %s", k+":", v))
	}

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
			addRow("Load", formatLoadAvg(info.LoadAverage, false))
		}
	}

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
		addRow("Compose", truncatePathForWidth(r.Metadata.ComposeFile, outerW-16))
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

	return renderCardBounded("Scan context", strings.Join(rows, "\n"), theme, Rect{W: outerW, H: height})
}
