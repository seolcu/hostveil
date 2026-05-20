package tui

import (
	"fmt"
	"sort"
	"strconv"
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

	// UltraWide and Wide use the new full-screen layout (no summary line — header covers it)
	if lm == LayoutUltraWide {
		if r.TotalFindings() == 0 {
			return m.renderUltraWideCleanDashboard(r, theme, width, height)
		}
		return m.renderUltraWideRiskDashboard(r, theme, width, height)
	}
	if lm == LayoutWide {
		if r.TotalFindings() == 0 {
			return m.renderWideCleanDashboard(r, theme, width, height)
		}
		return m.renderWideRiskDashboard(r, theme, width, height)
	}

	// Medium, Compact — height-budget layout
	if r.TotalFindings() == 0 {
		return m.renderCleanScanDashboard(r, theme, width, height)
	}

	return m.renderMediumRiskDashboard(r, theme, width, height)
}

// ─── Clean scan (0 findings) dashboard ─────────────────────────────────────

func (m *overviewModel) renderCleanScanDashboard(r *domain.ScanResult, theme Theme, width, height int) string {
	bodyHeight := height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	budget := dashboardHeightBudget(bodyHeight, LayoutMedium)

	used := budget.HeroH + budget.MainH + budget.WorkflowH + budget.GapH*2
	remaining := bodyHeight - used
	gap := budget.GapH
	if remaining > 0 {
		extraGap := clamp(remaining/2, 0, 1)
		gap += extraGap
	}
	_ = remaining

	full := width - 2

	// Hero: All clear + coverage limitation
	hero := m.renderAllClearHeroCard(theme, full, budget.HeroH)

	// Main: Area health + scan coverage side by side
	col2 := (width - 2) / 2
	areaHealth := m.renderAreaHealthCardScore(r, theme, col2, LayoutMedium)
	scanCov := m.renderScanCoverageCard(r, theme, col2)
	mainContent := lipgloss.JoinHorizontal(lipgloss.Top, areaHealth, "  ", scanCov)
	mainContent = fillHeight(mainContent, budget.MainH)

	// Bottom: next steps / workflow
	nextSteps := m.renderNextStepsCard(theme, full)
	nextSteps = fillHeight(nextSteps, budget.WorkflowH)

	return joinRows(
		hero,
		"",
		mainContent,
		"",
		nextSteps,
	)
}

func (m *overviewModel) renderMediumRiskDashboard(r *domain.ScanResult, theme Theme, width, height int) string {
	bodyHeight := height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	budget := dashboardHeightBudget(bodyHeight, LayoutMedium)

	used := budget.HeroH + budget.MainH + budget.WorkflowH + budget.GapH*2
	remaining := bodyHeight - used
	gap := budget.GapH
	if remaining > 0 {
		extraGap := clamp(remaining/2, 0, 1)
		gap += extraGap
	}
	_ = remaining

	full := width - 2

	// Hero: Risk summary
	hero := m.renderRiskSummaryHeroCard(r, theme, full, budget.HeroH)

	// Main: Next actions + Risk by area side by side (or stacked if narrow)
	var mainContent string
	col2 := (width - 2) / 2
	if width >= mediumWidth {
		nextActions := m.renderNextActionsCard(r, theme, col2)
		riskByArea := m.renderRiskByAreaCard(r, theme, col2)
		mainContent = lipgloss.JoinHorizontal(lipgloss.Top, nextActions, "  ", riskByArea)
	} else {
		colWidth := width - 2
		mainContent = m.renderNextActionsCard(r, theme, colWidth) + "\n\n" + m.renderRiskByAreaCard(r, theme, colWidth)
	}
	mainContent = fillHeight(mainContent, budget.MainH)

	// Bottom: workflow hint
	workflow := m.renderWorkflowHintCard(r, theme, full)
	workflow = fillHeight(workflow, budget.WorkflowH)

	return joinRows(
		hero,
		"",
		mainContent,
		"",
		workflow,
	)
}

func (m *overviewModel) renderWorkflowHintCard(r *domain.ScanResult, theme Theme, width int) string {
	if r.TotalFindings() == 0 {
		return renderCard("Next steps", "  Press 3 to export a clean report.", theme, width, 0)
	}
	steps := []string{
		"1. Press 2 to open Findings.",
		"2. Select the findings with the most critical severity first.",
		"3. Preview available fixes (press p), then apply safe changes.",
		"4. Rescan and export a report.",
	}
	var numbered []string
	for _, s := range steps {
		numbered = append(numbered, "  "+s)
	}
	return renderCard("Workflow hint", strings.Join(numbered, "\n"), theme, width, 0)
}

func (m *overviewModel) renderAllClearCard(theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	icon := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.Success)).
		Bold(true).
		Render("✓ All clear")

	msg := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Render("No findings detected in enabled checks.\nYour current scan passed the checks that actually ran.")

	return style.Render(icon + "\n" + msg)
}

func (m *overviewModel) renderScanCoverageCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Scan coverage")
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
		addRow("Compose", truncatePathForWidth(r.Metadata.ComposeFile, width-14))
	}

	if len(rows) == 1 {
		rows = append(rows, "")
	}

	return style.Render(title + "\n" + lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderRuntimeAdaptersCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Runtime / adapters")
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

	return style.Render(title + "\n" + lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderNextStepsCard(theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Next steps")

	steps := []string{
		"  • Press 3 to export a clean report.",
		"  • Place a docker-compose.yml file in the current directory for service scanning.",
		"  • Rescan after adding or changing services.",
		"  • Review Host Hardening recommendations even in clean scans.",
	}

	return style.Render(title + "\n" + strings.Join(steps, "\n"))
}

// ─── UltraWide Clean Dashboard (≥180x45, 0 findings) ────────────────────────

func (m *overviewModel) renderUltraWideCleanDashboard(r *domain.ScanResult, theme Theme, width, height int) string {
	bodyHeight := height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	budget := dashboardHeightBudget(bodyHeight, LayoutUltraWide)

	// Distribute remaining height into gaps only, not single sections
	used := budget.StatusH + budget.HeroH + budget.MainH + budget.SecondaryH + budget.TertiaryH + budget.WorkflowH + budget.GapH*5
	remaining := bodyHeight - used
	gap := budget.GapH
	if remaining > 0 {
		extraGap := clamp(remaining/6, 0, 2)
		gap += extraGap
		remaining -= extraGap * 5
	}
	_ = remaining // absorbed by fillHeight passthrough

	col4 := (width - 9) / 4
	col2 := (width - 3) / 2
	full := width - 2

	statusLine := m.renderStatusLineClean(r, theme)
	hero := m.renderAllClearHeroCard(theme, full, budget.HeroH)

	scanCov := m.renderScanCoverageCard(r, theme, col4)
	areaHealth := m.renderAreaHealthCardScore(r, theme, col4, LayoutUltraWide)
	runtime := m.renderRuntimeCard(r, theme, col4)
	adapters := m.renderAdaptersCard(r, theme, col4)
	grid4 := joinColumns([]string{scanCov, areaHealth, runtime, adapters}, []int{col4, col4, col4, col4}, 3)
	grid4 = fillHeight(grid4, budget.MainH)

	nextSteps := m.renderRecommendedNextStepsCard(r, theme, col2)
	meaning := m.renderWhatThisResultMeansCard(r, theme, col2)
	grid2a := lipgloss.JoinHorizontal(lipgloss.Top, nextSteps, "  ", meaning)
	grid2a = fillHeight(grid2a, budget.SecondaryH)

	reportPrev := m.renderReportPreviewCard(theme, col2)
	scanNotes := m.renderRecentScanNotesCard(r, theme, col2)
	grid2b := lipgloss.JoinHorizontal(lipgloss.Top, reportPrev, "  ", scanNotes)
	grid2b = fillHeight(grid2b, budget.TertiaryH)

	timeline := m.renderWorkflowTimelineCardClean(theme, full)
	timeline = fillHeight(timeline, budget.WorkflowH)

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

func (m *overviewModel) renderAllClearHeroCard(theme Theme, width, height int) string {
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
	return renderCard("", body, theme, width, height)
}

func (m *overviewModel) renderAreaHealthCardScore(r *domain.ScanResult, theme Theme, width int, mode LayoutMode) string {
	return renderCard("Area health", strings.Join(renderAreaHealthBars(r, width, mode, theme), "\n"), theme, width, 0)
}

func (m *overviewModel) renderRuntimeCard(r *domain.ScanResult, theme Theme, width int) string {
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
			addRow("Load avg", formatLoadAvg(info.LoadAverage, false))
		}
	}
	return renderCard("Runtime", strings.Join(rows, "\n"), theme, width, 0)
}

func (m *overviewModel) renderAdaptersCard(r *domain.ScanResult, theme Theme, width int) string {
	var rows []string
	if len(r.Metadata.Adapters) > 0 {
		for _, a := range r.Metadata.Adapters {
			status := "detected"
			rows = append(rows, fmt.Sprintf("  %-12s %s", a.Name+":", status))
		}
	}
	rows = append(rows, "  Missing        none")
	return renderCard("Adapters", strings.Join(rows, "\n"), theme, width, 0)
}

func (m *overviewModel) renderRecommendedNextStepsCard(r *domain.ScanResult, theme Theme, width int) string {
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
	return renderCard("Recommended next steps", strings.Join(numbered, "\n"), theme, width, 0)
}

func (m *overviewModel) renderWhatThisResultMeansCard(r *domain.ScanResult, theme Theme, width int) string {
	text := `  This is a clean result for the checks that actually ran.
  Because no Compose services were discovered, service-level checks
  (public bindings, container privileges, filesystem risks) were limited.
  Add docker-compose.yml and rescan for full coverage.`
	return renderCard("What this result means", text, theme, width, 0)
}

func (m *overviewModel) renderReportPreviewCard(theme Theme, width int) string {
	text := `  Current report status: ready
  Suggested format: Markdown or HTML for sharing

  [3] Report → choose JSON / SARIF / Markdown / HTML`
	return renderCard("Report preview", text, theme, width, 0)
}

func (m *overviewModel) renderRecentScanNotesCard(r *domain.ScanResult, theme Theme, width int) string {
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
	return renderCard("Recent scan notes", strings.Join(lines, "\n"), theme, width, 0)
}

func (m *overviewModel) renderWorkflowTimelineCardClean(theme Theme, width int) string {
	steps := []string{
		"1 Scan completed ✓",
		"2 Findings analyzed ✓",
		"3 Report ready ○",
		"4 Export report ○",
		"5 Rescan after changes ○",
	}
	line := "  " + strings.Join(steps, "    ")
	return renderCard("Workflow timeline", line, theme, width, 0)
}

// ─── UltraWide Risk Dashboard (≥180x45, findings > 0) ──────────────────────

func (m *overviewModel) renderUltraWideRiskDashboard(r *domain.ScanResult, theme Theme, width, height int) string {
	bodyHeight := height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	budget := dashboardHeightBudget(bodyHeight, LayoutUltraWide)

	used := budget.StatusH + budget.HeroH + budget.MainH + budget.SecondaryH + budget.TertiaryH + budget.WorkflowH + budget.GapH*5
	remaining := bodyHeight - used
	gap := budget.GapH
	if remaining > 0 {
		extraGap := clamp(remaining/6, 0, 2)
		gap += extraGap
		remaining -= extraGap * 5
	}
	_ = remaining

	col4 := (width - 9) / 4
	col2 := (width - 3) / 2
	full := width - 2

	statusLine := m.renderStatusLineRisk(r, theme)
	hero := m.renderRiskSummaryHeroCard(r, theme, full, budget.HeroH)

	grid4 := m.renderUltraWideRiskGrid4(r, theme, col4, 3)
	grid4 = fillHeight(grid4, budget.MainH)

	workflow := m.renderRiskWorkflowCard(r, theme, col2)
	whyScore := m.renderWhyScoreLowCard(r, theme, col2)
	grid2a := lipgloss.JoinHorizontal(lipgloss.Top, workflow, "  ", whyScore)
	grid2a = fillHeight(grid2a, budget.SecondaryH)

	selectedPrev := m.renderSelectedPreviewCard(r, theme, col2)
	scanCtx := m.renderScanContextCard(r, theme, col2)
	grid2b := lipgloss.JoinHorizontal(lipgloss.Top, selectedPrev, "  ", scanCtx)
	grid2b = fillHeight(grid2b, budget.TertiaryH)

	timeline := m.renderWorkflowTimelineCardRisk(theme, full)
	timeline = fillHeight(timeline, budget.WorkflowH)

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

func (m *overviewModel) renderUltraWideRiskGrid4(r *domain.ScanResult, theme Theme, colWidth, gap int) string {
	nextActions := m.renderNextActionsCard(r, theme, colWidth)
	riskByArea := m.renderRiskByAreaCardFindings(r, theme, colWidth)
	affectedSvcs := m.renderAffectedServicesCard(r, theme, colWidth)
	fixQueue := m.renderFixQueueCard(r, theme, colWidth)

	return joinColumns(
		[]string{nextActions, riskByArea, affectedSvcs, fixQueue},
		[]int{colWidth, colWidth, colWidth, colWidth},
		gap,
	)
}

func (m *overviewModel) renderRiskSummaryHeroCard(r *domain.ScanResult, theme Theme, width, height int) string {
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
	return renderCard("Risk summary", body, theme, width, height)
}

func (m *overviewModel) renderRiskByAreaCardFindings(r *domain.ScanResult, theme Theme, width int) string {
	return m.renderRiskByAreaCard(r, theme, width)
}

func (m *overviewModel) renderRiskWorkflowCard(r *domain.ScanResult, theme Theme, width int) string {
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
	return renderCard("Recommended workflow", strings.Join(numbered, "\n"), theme, width, 0)
}

func (m *overviewModel) renderWhyScoreLowCard(r *domain.ScanResult, theme Theme, width int) string {
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
	return renderCard("Why the score is low", text, theme, width, 0)
}

func (m *overviewModel) renderSelectedPreviewCard(r *domain.ScanResult, theme Theme, width int) string {
	if len(r.Findings) == 0 {
		return renderCard("Selected preview", "  No findings to preview.", theme, width, 0)
	}

	// Find first fixable finding
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

	return renderCard("Selected preview", body.String(), theme, width, 0)
}

func (m *overviewModel) renderWorkflowTimelineCardRisk(theme Theme, width int) string {
	steps := []string{
		"1 Scan completed ✓",
		"2 Findings grouped ✓",
		"3 Preview fixes ○",
		"4 Apply / rescan ○",
		"5 Export report ○",
	}
	line := "  " + strings.Join(steps, "    ")
	return renderCard("Workflow timeline", line, theme, width, 0)
}

// ─── Wide Clean Dashboard (≥120x35, 0 findings) ─────────────────────────────

func (m *overviewModel) renderWideCleanDashboard(r *domain.ScanResult, theme Theme, width, height int) string {
	bodyHeight := height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	budget := dashboardHeightBudget(bodyHeight, LayoutWide)

	// Distribute remaining into gaps
	used := budget.StatusH + budget.HeroH + budget.MainH + budget.SecondaryH + budget.WorkflowH + budget.GapH*4
	remaining := bodyHeight - used
	gap := budget.GapH
	if remaining > 0 {
		extraGap := clamp(remaining/4, 0, 2)
		gap += extraGap
	}
	_ = remaining

	col3 := (width - 6) / 3
	col2 := (width - 3) / 2
	full := width - 2

	statusLine := m.renderStatusLineClean(r, theme)

	hero := m.renderAllClearHeroCard(theme, full, budget.HeroH)

	allClear := m.renderAllClearCard(theme, col3)
	scanCov := m.renderScanCoverageCard(r, theme, col3)
	runtimeAd := m.renderRuntimeAdaptersCard(r, theme, col3)
	mainGrid := lipgloss.JoinHorizontal(lipgloss.Top, allClear, "  ", scanCov, "  ", runtimeAd)
	mainGrid = fillHeight(mainGrid, budget.MainH)

	areaHealth := m.renderAreaHealthCardScore(r, theme, col2, LayoutWide)
	nextSteps := m.renderNextStepsCard(theme, col2)
	secondaryGrid := lipgloss.JoinHorizontal(lipgloss.Top, areaHealth, "  ", nextSteps)
	secondaryGrid = fillHeight(secondaryGrid, budget.SecondaryH)

	timeline := m.renderWorkflowTimelineCardClean(theme, full)
	timeline = fillHeight(timeline, budget.WorkflowH)

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

// ─── Wide Risk Dashboard (≥120x35, findings > 0) ────────────────────────────

func (m *overviewModel) renderWideRiskDashboard(r *domain.ScanResult, theme Theme, width, height int) string {
	bodyHeight := height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	budget := dashboardHeightBudget(bodyHeight, LayoutWide)

	used := budget.StatusH + budget.HeroH + budget.MainH + budget.SecondaryH + budget.WorkflowH + budget.GapH*4
	remaining := bodyHeight - used
	gap := budget.GapH
	if remaining > 0 {
		extraGap := clamp(remaining/4, 0, 2)
		gap += extraGap
	}
	_ = remaining

	col3 := (width - 6) / 3
	col2 := (width - 2) / 2
	full := width - 2

	statusLine := m.renderStatusLineRisk(r, theme)

	hero := m.renderRiskSummaryHeroCard(r, theme, full, budget.HeroH)

	nextActions := m.renderNextActionsCard(r, theme, col3)
	riskByArea := m.renderRiskByAreaCard(r, theme, col3)
	affectedSvcs := m.renderAffectedServicesCard(r, theme, col3)
	mainGrid := joinColumns([]string{nextActions, riskByArea, affectedSvcs}, []int{col3, col3, col3}, 3)
	mainGrid = fillHeight(mainGrid, budget.MainH)

	fixQueue := m.renderFixQueueCard(r, theme, col2)
	scanCtx := m.renderScanContextCard(r, theme, col2)
	secondaryGrid := lipgloss.JoinHorizontal(lipgloss.Top, fixQueue, "  ", scanCtx)
	secondaryGrid = fillHeight(secondaryGrid, budget.SecondaryH)

	timeline := m.renderWorkflowTimelineCardRisk(theme, full)
	timeline = fillHeight(timeline, budget.WorkflowH)

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

func (m *overviewModel) renderNextActionsCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Next actions")
	var rows []string

	// Sort findings: severity order (Critical > High > Medium > Low), then remediation (Auto > Review > Manual)
	sorted := make([]domain.Finding, len(r.Findings))
	copy(sorted, r.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity < sorted[j].Severity
		}
		return sorted[i].Remediation < sorted[j].Remediation
	})

	maxActions := 3
	if width < 60 {
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
		maxTitle := width - len(sevLabel) - len(svc) - 12
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

	return style.Render(title + "\n" + strings.Join(rows, "\n"))
}

func (m *overviewModel) renderRiskByAreaCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Risk by area")
	var rows []string

	// Count findings per axis (count centered — no score language in Dashboard)
	axisCounts := make(map[domain.Axis]int)
	for _, f := range r.Findings {
		axisCounts[f.Axis]++
	}

	for _, axis := range domain.AllAxes() {
		count := axisCounts[axis]

		labelText := axis.Label()
		if width < 45 {
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

		label := lipgloss.NewStyle().
			Width(22).
			Render(labelText)

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

	return style.Render(title + "\n" + strings.Join(rows, "\n"))
}

func (m *overviewModel) renderAffectedServicesCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Affected services")
	var rows []string

	// Group by service
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

		// Narrow cards show abbreviated breakdown
		compact := width < 45
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

		spacer := width - lipgloss.Width(stripANSI(svcLabel)) - lipgloss.Width(countStr) - 8
		if spacer < 1 {
			spacer = 1
		}

		rows = append(rows, fmt.Sprintf("  %s%s%s", svcLabel, strings.Repeat(" ", spacer), countLabel))
	}

	if len(rows) == 0 {
		rows = append(rows, "  No services affected")
	}

	return style.Render(title + "\n" + strings.Join(rows, "\n"))
}

func (m *overviewModel) renderHostCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	info := r.Metadata.HostRuntime
	if info == nil {
		return style.Render("No host data")
	}

	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("%-12s %s", k+":", v))
	}

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
		loadStr := formatLoadAvg(info.LoadAverage, false)
		fields := strings.Fields(info.LoadAverage)
		if len(fields) > 0 {
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
				switch {
				case v > 2.0:
					loadStr += " ↑"
				case v > 1.0:
					loadStr += " →"
				}
			}
		}
		addRow("Load", loadStr)
	}

	return style.Render(lipgloss.JoinVertical(lipgloss.Left, rows...))
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

func (m *overviewModel) renderFixQueueCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Fix queue")
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

	return style.Render(title + "\n" + strings.Join(rows, "\n"))
}

func (m *overviewModel) renderScanContextCard(r *domain.ScanResult, theme Theme, width int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Scan context")
	var rows []string
	addRow := func(k, v string) {
		rows = append(rows, fmt.Sprintf("%-12s %s", k+":", v))
	}

	// Host info
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
			loadStr := formatLoadAvg(info.LoadAverage, false)
			fields := strings.Fields(info.LoadAverage)
			if len(fields) > 0 {
				if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
					switch {
					case v > 2.0:
						loadStr += " ↑"
					case v > 1.0:
						loadStr += " →"
					}
				}
			}
			addRow("Load", loadStr)
		}
	}

	// Scan context
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
		addRow("Compose", truncatePathForWidth(r.Metadata.ComposeFile, width-14))
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

	return style.Render(title + "\n" + lipgloss.JoinVertical(lipgloss.Left, rows...))
}

func (m *overviewModel) renderRecommendationCard(r *domain.ScanResult, theme Theme, width int) string {
	if len(r.Findings) == 0 {
		return ""
	}

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render("Recommendation")
	var desc string

	// Find axis with the most findings (count centered, no score language)
	axisCounts := make(map[string]int)
	for _, f := range r.Findings {
		axisCounts[f.Axis.Label()]++
	}
	mostAxis := ""
	mostCount := 0
	for axis, c := range axisCounts {
		if c > mostCount {
			mostCount = c
			mostAxis = axis
		}
	}

	grade := r.ScoreReport.Grade()
	if mostCount == 0 {
		desc = "Overall security posture is Good. Maintain current practices."
	} else {
		desc = fmt.Sprintf("Overall risk is %s, driven by %d %s-related finding(s).",
			grade, mostCount, strings.ToLower(mostAxis))

		lowLabel := strings.ToLower(mostAxis)
		switch {
		case strings.Contains(lowLabel, "exposure"):
			desc += " Start with public bindings and reverse proxy configuration first."
		case strings.Contains(lowLabel, "sensitive"):
			desc += " Review secrets management, env variables, and data volume permissions."
		case strings.Contains(lowLabel, "permission"):
			desc += " Audit file permissions, drop capabilities, and restrict privilege escalation."
		case strings.Contains(lowLabel, "supply"):
			desc += " Pin image versions and enable automatic security updates."
		case strings.Contains(lowLabel, "host"):
			desc += " Harden the host: SSH config, firewall rules, kernel parameters, and defenses."
		}
	}

	style := lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	return style.Render(title + "\n" + desc)
}
