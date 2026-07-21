package tui

import (
	"fmt"
	"image/color"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/model"
)

// Palette — identical hex to the web UI ("Instrument" system). lipgloss v2
// renders these as truecolor and degrades gracefully on limited terminals.
var (
	cLine  = lipgloss.Color("#333b46")
	cBone  = lipgloss.Color("#e7e3d8")
	cSlate = lipgloss.Color("#7c8692")
	cCrit  = lipgloss.Color("#e5484d")
	cHigh  = lipgloss.Color("#e8843c")
	cMed   = lipgloss.Color("#e6c14a")
	cLow   = lipgloss.Color("#6b7480")
	cSafe  = lipgloss.Color("#46c69a")
)

var (
	styleBone  = lipgloss.NewStyle().Foreground(cBone)
	styleDim   = lipgloss.NewStyle().Foreground(cSlate)
	styleSafe  = lipgloss.NewStyle().Foreground(cSafe)
	styleBrand = lipgloss.NewStyle().Foreground(cBone).Bold(true)
	styleSel   = lipgloss.NewStyle().Foreground(cBone).Background(cLine).Bold(true)
	styleTrack = lipgloss.NewStyle().Foreground(cLine)
)

func severityColor(s model.Severity) color.Color {
	switch s {
	case model.SeverityCritical:
		return cCrit
	case model.SeverityHigh:
		return cHigh
	case model.SeverityMedium:
		return cMed
	default:
		return cLow
	}
}

// band maps a 0-100 health score to its meter color (safe→crit heat).
func band(v uint8) color.Color {
	switch {
	case v >= 80:
		return cSafe
	case v >= 50:
		return cMed
	case v >= 25:
		return cHigh
	default:
		return cCrit
	}
}

// meter renders a segmented bar: filled blocks in c, empty in the track.
func meter(pct uint8, width int, c color.Color) string {
	filled := int(pct) * width / 100
	if filled > width {
		filled = width
	}
	on := lipgloss.NewStyle().Foreground(c).Render(strings.Repeat("█", filled))
	off := styleTrack.Render(strings.Repeat("░", width-filled))
	return on + off
}

func (m *appModel) View() tea.View {
	var content string
	switch m.mode {
	case modeScanning:
		content = "\n  " + styleDim.Render(m.status) + "\n"
	case modeList:
		content = m.viewList()
	case modeDetail:
		content = m.viewDetail()
	case modePreview:
		content = m.viewPreview()
	case modeMessage:
		content = m.viewMessage()
	case modeHistory:
		content = m.viewHistory()
	case modeRollbackConfirm:
		content = m.viewRollbackConfirm()
	}
	return tea.View{Content: content, AltScreen: true}
}

func (m *appModel) rule() string {
	w := m.width
	if w < 1 {
		w = 1
	}
	return styleTrack.Render(strings.Repeat("─", w))
}

// header renders the status bar: brand + the exposure gauge (SECURITY
// meter + score), then the per-axis bars.
func (m *appModel) header() string {
	var b strings.Builder
	sc := m.report.Score.Overall
	b.WriteString(styleDim.Render("▚ ") + styleBrand.Render("hostveil"))
	b.WriteString("   " + styleDim.Render("SECURITY ") + meter(sc, 18, band(sc)) +
		styleBone.Render(fmt.Sprintf(" %d", sc)) + styleDim.Render("/100"))
	b.WriteString("\n")
	b.WriteString(m.axesLine())
	b.WriteString("\n")
	if line := m.deltaLine(); line != "" {
		b.WriteString(line + "\n")
	}
	return b.String()
}

// deltaLine summarises what moved since the previous scan. The CLI prints
// the same counts and then names the findings; here it stays one line —
// the list below already shows what is outstanding, and the question this
// answers is only "did the last round of fixes help?". Nothing is rendered
// when there is no previous scan to compare against.
func (m *appModel) deltaLine() string {
	if !m.delta.HasChanges() {
		return ""
	}
	var parts []string
	if n := len(m.delta.Resolved); n > 0 {
		parts = append(parts, styleSafe.Render(fmt.Sprintf("✓ %d resolved", n)))
	}
	if n := len(m.delta.New); n > 0 {
		parts = append(parts, lipgloss.NewStyle().Foreground(cHigh).Render(fmt.Sprintf("+ %d new", n)))
	}
	if n := len(m.delta.Changed); n > 0 {
		parts = append(parts, styleBone.Render(fmt.Sprintf("~ %d changed", n)))
	}
	return styleDim.Render("since last scan  ") + strings.Join(parts, styleDim.Render("   "))
}

func (m *appModel) axesLine() string {
	var parts []string
	for _, ax := range m.report.Score.Axes {
		label := styleDim.Render(fmt.Sprintf("%-9s", ax.ID))
		switch {
		case !ax.Applicable:
			parts = append(parts, label+styleTrack.Render(strings.Repeat("░", 8))+styleDim.Render(" N/A"))
		case ax.Degraded:
			// Scored, but from an incomplete picture — the "~" says so, since
			// a bare number here reads as a full result.
			parts = append(parts, label+meter(ax.Score, 8, band(ax.Score))+styleBone.Render(fmt.Sprintf(" %d~", ax.Score)))
		default:
			parts = append(parts, label+meter(ax.Score, 8, band(ax.Score))+styleBone.Render(fmt.Sprintf(" %-3d", ax.Score)))
		}
	}
	return strings.Join(parts, styleDim.Render("   "))
}

const listHint = "↑/↓ move   enter details   f fix   space select   a fix marked\n" +
	"s severity   d domain   x fixable   c clear   h history   r rescan   q quit"

func (m *appModel) viewList() string {
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString(m.rule() + "\n")

	fl := m.filterLine()

	// Empty list: distinguish a clean host from a too-narrow filter.
	if len(m.active) == 0 {
		if fl != "" {
			b.WriteString(fl + "\n")
			b.WriteString("\n" + styleDim.Render("  No findings match the filter.") + "\n")
		} else {
			b.WriteString("\n" + styleSafe.Render("  No problems found. Clean.") + "\n")
		}
		b.WriteString(m.footer("c clear   r rescan   q quit"))
		return b.String()
	}

	reserved := 8
	if fl != "" {
		reserved++
	}
	visible := m.height - reserved
	if visible < 1 {
		visible = 1
	}
	m.offset = scrollOffset(m.cursor, len(m.active), visible, m.offset)
	end := m.offset + visible
	if end > len(m.active) {
		end = len(m.active)
	}

	// Head: shown[/total] · selected · scroll range.
	count := fmt.Sprintf("FINDINGS · %d", len(m.active))
	if total := m.activeTotal(); total != len(m.active) {
		count = fmt.Sprintf("FINDINGS · %d/%d", len(m.active), total)
	}
	head := styleDim.Render(count)
	if n := len(m.selected); n > 0 {
		head += styleSafe.Render(fmt.Sprintf("   ✓ %d marked", n))
	}
	if len(m.active) > visible {
		head += styleDim.Render(fmt.Sprintf("      %d–%d", m.offset+1, end))
	}
	b.WriteString(head + "\n")
	if fl != "" {
		b.WriteString(fl + "\n")
	}

	for i := m.offset; i < end; i++ {
		b.WriteString(m.findingRow(m.active[i], i == m.cursor) + "\n")
	}
	b.WriteString(m.footer(listHint))
	return b.String()
}

// activeTotal counts findings that are not fixed, ignoring the filter — the
// denominator for the "shown/total" indicator.
func (m *appModel) activeTotal() int {
	n := 0
	for _, f := range m.report.Findings {
		if !f.Fixed {
			n++
		}
	}
	return n
}

// findingRow renders one heat-gutter row: pick marker + severity gutter +
// label + id + title + service. The cursor row is inverse-video. The pick
// marker (✓ / ·) is only shown on auto-fixable rows, since only those can be
// batch-selected.
func (m *appModel) findingRow(f model.Finding, cursor bool) string {
	sevC := severityColor(f.Severity)
	gutter := lipgloss.NewStyle().Foreground(sevC).Render("▌")
	mark := "  "
	if f.Remediation == model.RemediationAuto {
		if m.selected[f.Key()] {
			mark = styleSafe.Render("✓ ")
		} else {
			mark = styleDim.Render("· ")
		}
	}
	sev := sevAbbr(f.Severity)
	title := truncate(f.Title, m.width-46)
	if cursor {
		return gutter + mark + styleSel.Render(padRight(fmt.Sprintf("%-4s %-13s %s", sev, f.ID, title), m.width-3))
	}
	return gutter + mark + lipgloss.NewStyle().Foreground(sevC).Render(sev) +
		styleDim.Render(fmt.Sprintf(" %-13s ", f.ID)) + styleBone.Render(title) + serviceSuffixTUI(f)
}

// sourceLabel is the short domain name shown in the filter line, matching
// the score axis labels.
func sourceLabel(s model.Source) string {
	switch s {
	case model.SourceCompose:
		return "Container"
	case model.SourceSSH:
		return "SSH"
	case model.SourceFirewall:
		return "Firewall"
	case model.SourceUpdates:
		return "Updates"
	case model.SourceCVE:
		return "CVEs"
	case model.SourcePorts:
		return "Ports"
	case model.SourceAccounts:
		return "Accounts"
	case model.SourceFilePerms:
		return "File perms"
	case model.SourceAgent:
		return "AI agents"
	default:
		return s.String()
	}
}

// filterLine describes the active filter, or "" when nothing is filtered.
func (m *appModel) filterLine() string {
	var parts []string
	if m.filter.MinSeverity != nil {
		parts = append(parts, "sev≥"+strings.ToUpper(m.filter.MinSeverity.String()))
	}
	if m.filter.Source != model.SourceUnset {
		parts = append(parts, sourceLabel(m.filter.Source))
	}
	if m.filter.FixableOnly {
		parts = append(parts, "fixable")
	}
	if len(parts) == 0 {
		return ""
	}
	return styleDim.Render("FILTER  ") + styleBone.Render(strings.Join(parts, " · "))
}

func sevAbbr(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "CRIT"
	case model.SeverityHigh:
		return "HIGH"
	case model.SeverityMedium:
		return "MED"
	default:
		return "LOW"
	}
}

func serviceSuffixTUI(f model.Finding) string {
	if f.Service == "" {
		return ""
	}
	return styleDim.Render("  (" + f.Service + ")")
}

func (m *appModel) viewDetail() string {
	f := m.active[m.cursor]
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString(m.rule() + "\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(severityColor(f.Severity)).Bold(true).Render(strings.ToUpper(f.Severity.String())) +
		"  " + styleBrand.Render(f.Title) + "\n")
	meta := strings.ToUpper(f.ID + "  ·  " + f.Remediation.String())
	if f.Service != "" {
		meta += "  ·  SERVICE: " + f.Service
	}
	b.WriteString(styleDim.Render(meta) + "\n\n")
	b.WriteString(styleBone.Render(wrap(f.Description, min(m.width-4, 78))) + "\n\n")
	if f.HowToFix != "" {
		b.WriteString(styleDim.Render("HOW TO FIX") + "\n")
		b.WriteString(styleBone.Render(wrap(f.HowToFix, min(m.width-4, 78))) + "\n")
	}
	hint := "esc back   q list"
	if f.IsFixable() {
		hint = "f apply fix   " + hint
	}
	b.WriteString(m.footer(hint))
	return b.String()
}

func (m *appModel) viewPreview() string {
	var b strings.Builder
	b.WriteString(styleDim.Render("FIX PREVIEW") + "\n")
	b.WriteString(styleBrand.Render(m.preview.Label) + "\n")
	b.WriteString(m.rule() + "\n\n")

	if len(m.preview.Actions) > 1 {
		b.WriteString(styleDim.Render("Alternatives (press a number):") + "\n")
		for _, a := range m.preview.Actions {
			marker := "  "
			if a.Index == m.previewAction {
				marker = lipgloss.NewStyle().Foreground(cBone).Render("› ")
			}
			b.WriteString(marker + styleBone.Render(fmt.Sprintf("[%d] %s", a.Index, a.Label)) + "\n")
		}
		b.WriteString("\n")
	}

	a := m.preview.Actions[m.previewAction]
	if a.Warning != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(cHigh).Render("⚠  "+a.Warning) + "\n\n")
	}
	switch a.Type {
	case "edit", "mode":
		b.WriteString(renderDiff(a.Diff))
	case "exec":
		b.WriteString(styleDim.Render("These commands will run:") + "\n")
		for _, cmd := range a.Commands {
			b.WriteString(styleDim.Render("  $ "+strings.Join(cmd, " ")) + "\n")
		}
	default:
		// Never leave the apply/cancel footer with an empty body above it.
		b.WriteString(styleDim.Render("(no preview available for action type "+a.Type+")") + "\n")
	}
	b.WriteString(m.footer("y apply   n cancel"))
	return b.String()
}

// viewHistory lists every applied fix, newest first, so a fix applied here
// can be undone here rather than only from the CLI. Non-reversible
// (command) fixes are dimmed: they are part of the record but there is
// nothing file-backed to restore.
func (m *appModel) viewHistory() string {
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString(m.rule() + "\n")

	reserved := 8
	visible := m.height - reserved
	if visible < 1 {
		visible = 1
	}
	m.cpOffset = scrollOffset(m.cpCursor, len(m.checkpoints), visible, m.cpOffset)
	end := m.cpOffset + visible
	if end > len(m.checkpoints) {
		end = len(m.checkpoints)
	}

	head := styleDim.Render(fmt.Sprintf("APPLIED FIXES · %d", len(m.checkpoints)))
	if len(m.checkpoints) > visible {
		head += styleDim.Render(fmt.Sprintf("      %d–%d", m.cpOffset+1, end))
	}
	b.WriteString(head + "\n")

	for i := m.cpOffset; i < end; i++ {
		b.WriteString(m.checkpointRow(m.checkpoints[i], i == m.cpCursor) + "\n")
	}
	b.WriteString(m.footer("↑/↓ move   enter roll back   esc back   q list"))
	return b.String()
}

func (m *appModel) checkpointRow(cp model.Checkpoint, cursor bool) string {
	when := cp.CreatedAt.Local().Format("01-02 15:04")
	label := truncate(cp.Label, m.width-40)
	line := fmt.Sprintf("%-11s %-15s %s", when, cp.FindingID, label)
	if cursor {
		return styleSel.Render(padRight(line, m.width-1))
	}
	if !cp.Reversible {
		return styleDim.Render(line)
	}
	return styleDim.Render(when+" ") + styleBone.Render(fmt.Sprintf("%-15s ", cp.FindingID)) +
		styleBone.Render(label)
}

// viewRollbackConfirm mirrors viewPreview's y/n gesture, showing the diff
// the rollback would revert so the decision is made on evidence.
func (m *appModel) viewRollbackConfirm() string {
	cp := m.checkpoints[m.cpCursor]
	var b strings.Builder
	b.WriteString(styleDim.Render("ROLL BACK") + "\n")
	b.WriteString(styleBrand.Render(cp.Label) + "\n")
	b.WriteString(m.rule() + "\n\n")
	b.WriteString(styleDim.Render("Restores:") + "\n")
	for _, p := range cp.Files {
		b.WriteString(styleBone.Render("  "+p) + "\n")
	}
	b.WriteString("\n")
	if cp.RestartService != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(cHigh).
			Render("⚠  You may need to restart '"+cp.RestartService+"' afterwards.") + "\n\n")
	}
	if cp.Diff != "" {
		b.WriteString(styleDim.Render("This change will be reverted:") + "\n")
		b.WriteString(renderDiff(cp.Diff))
	}
	b.WriteString(m.footer("y roll back   n cancel"))
	return b.String()
}

func (m *appModel) viewMessage() string {
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString(m.rule() + "\n\n  " + styleBone.Render(m.status) + "\n")
	b.WriteString(m.footer("press any key to continue"))
	return b.String()
}

func (m *appModel) footer(hint string) string {
	return "\n" + m.rule() + "\n" + styleDim.Render(hint)
}

func renderDiff(diff string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(diff, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			b.WriteString(styleSafe.Render(line) + "\n")
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			b.WriteString(lipgloss.NewStyle().Foreground(cCrit).Render(line) + "\n")
		default:
			b.WriteString(styleDim.Render(line) + "\n")
		}
	}
	return b.String()
}

// scrollOffset returns a new window start that keeps cursor within the
// visible rows, clamped to the list bounds.
func scrollOffset(cursor, total, visible, offset int) int {
	if cursor < offset {
		offset = cursor
	}
	if cursor >= offset+visible {
		offset = cursor - visible + 1
	}
	if max := total - visible; offset > max {
		offset = max
	}
	if offset < 0 {
		offset = 0
	}
	return offset
}

func truncate(s string, max int) string {
	if max < 4 || len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func padRight(s string, n int) string {
	if lipgloss.Width(s) >= n || n < 0 {
		return s
	}
	return s + strings.Repeat(" ", n-lipgloss.Width(s))
}

func wrap(s string, width int) string {
	if width < 8 {
		width = 8
	}
	words := strings.Fields(s)
	var b strings.Builder
	ll := 0
	for i, w := range words {
		if i > 0 && ll+1+len(w) > width {
			b.WriteString("\n")
			ll = 0
		} else if i > 0 {
			b.WriteString(" ")
			ll++
		}
		b.WriteString(w)
		ll += len(w)
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
