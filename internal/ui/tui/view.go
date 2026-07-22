package tui

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

// styles is one theme resolved into the colors and lipgloss styles the views
// draw with. lipgloss v2 renders these as truecolor and degrades gracefully
// on limited terminals.
//
// This used to be a package-level palette, fixed at init and duplicated by
// hand in the web dashboard's CSS. The hexes now come from
// internal/ui/theme — one registry, shared with the dashboard — and a themed
// TUI needs to rebuild them at runtime, which a package var cannot do.
type styles struct {
	cInk   color.Color
	cLine  color.Color
	cBone  color.Color
	cSlate color.Color
	cCrit  color.Color
	cHigh  color.Color
	cMed   color.Color
	cLow   color.Color
	cSafe  color.Color

	bone  lipgloss.Style
	dim   lipgloss.Style
	safe  lipgloss.Style
	brand lipgloss.Style
	sel   lipgloss.Style
	track lipgloss.Style
}

func newStyles(t theme.Theme) *styles {
	p := t.Palette
	s := &styles{
		cInk:   lipgloss.Color(p.Ink),
		cLine:  lipgloss.Color(p.Line2),
		cBone:  lipgloss.Color(p.Bone),
		cSlate: lipgloss.Color(p.Slate),
		cCrit:  lipgloss.Color(p.Crit),
		cHigh:  lipgloss.Color(p.High),
		cMed:   lipgloss.Color(p.Med),
		cLow:   lipgloss.Color(p.Low),
		cSafe:  lipgloss.Color(p.Safe),
	}
	s.bone = lipgloss.NewStyle().Foreground(s.cBone)
	s.dim = lipgloss.NewStyle().Foreground(s.cSlate)
	s.safe = lipgloss.NewStyle().Foreground(s.cSafe)
	s.brand = lipgloss.NewStyle().Foreground(s.cBone).Bold(true)
	s.sel = lipgloss.NewStyle().Foreground(s.cBone).Background(s.cLine).Bold(true)
	s.track = lipgloss.NewStyle().Foreground(s.cLine)
	return s
}

// sty returns the active styles, building them on first use. The lazy build
// is deliberate: an appModel is a plain struct that several call sites (and
// every layout test) construct as a literal, and a zero value must render in
// the default theme rather than in no colors at all.
func (m *appModel) sty() *styles {
	if m.st == nil {
		if m.th.ID == "" {
			m.th = theme.Default()
		}
		m.st = newStyles(m.th)
	}
	return m.st
}

// setTheme switches the palette the next render draws with.
func (m *appModel) setTheme(t theme.Theme) {
	if t.ID == "" {
		t = theme.Default()
	}
	m.th, m.st = t, newStyles(t)
}

func (s *styles) severityColor(sev model.Severity) color.Color {
	switch sev {
	case model.SeverityCritical:
		return s.cCrit
	case model.SeverityHigh:
		return s.cHigh
	case model.SeverityMedium:
		return s.cMed
	default:
		return s.cLow
	}
}

// band maps a 0-100 health score to its meter color (safe→crit heat).
func (s *styles) band(v uint8) color.Color {
	switch {
	case v >= 80:
		return s.cSafe
	case v >= 50:
		return s.cMed
	case v >= 25:
		return s.cHigh
	default:
		return s.cCrit
	}
}

// meter renders a segmented bar: filled blocks in c, empty in the track.
func (s *styles) meter(pct uint8, width int, c color.Color) string {
	filled := int(pct) * width / 100
	if filled > width {
		filled = width
	}
	on := lipgloss.NewStyle().Foreground(c).Render(strings.Repeat("█", filled))
	off := s.track.Render(strings.Repeat("░", width-filled))
	return on + off
}

func (m *appModel) View() tea.View {
	s := m.sty()
	var content string
	switch m.mode {
	case modeScanning:
		content = "\n  " + s.dim.Render(m.status) + "\n"
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
	case modeTheme:
		content = m.viewTheme()
	}
	// Paint the terminal background too. Without it a theme only recolors the
	// text and the terminal's own background shows through every gap, which
	// reads as a broken palette rather than a chosen one. Bubble Tea resets
	// this to the terminal's default when the program exits — note that a
	// terminal whose background was itself set by an earlier escape sequence
	// comes back to its default rather than to that value.
	return tea.View{Content: content, AltScreen: true, BackgroundColor: s.cInk}
}

func (m *appModel) rule() string {
	w := m.width
	if w < 1 {
		w = 1
	}
	return m.sty().track.Render(strings.Repeat("─", w))
}

// header renders the status bar: brand + the exposure gauge (SECURITY
// meter + score), then the per-axis bars.
func (m *appModel) header() string {
	s := m.sty()
	var b strings.Builder
	sc := m.report.Score.Overall
	b.WriteString(s.dim.Render("▚ ") + s.brand.Render("hostveil"))
	// Everything but the meter is fixed width: "▚ " + "hostveil" + a
	// three-space gap + "SECURITY " + " NNN" + "/100". The meter absorbs
	// whatever is left, so the gauge shrinks with the terminal instead of
	// running off the end of a narrow one.
	const gaugeChrome = 2 + 8 + 3 + 9 + 4 + 4
	meterW := 18
	if m.width > 0 && m.width-gaugeChrome < meterW {
		meterW = max(4, m.width-gaugeChrome)
	}
	b.WriteString("   " + s.dim.Render("SECURITY ") + s.meter(sc, meterW, s.band(sc)) +
		s.bone.Render(fmt.Sprintf(" %d", sc)) + s.dim.Render("/100"))
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
	s := m.sty()
	var parts []string
	if n := len(m.delta.Resolved); n > 0 {
		parts = append(parts, s.safe.Render(fmt.Sprintf("✓ %d resolved", n)))
	}
	if n := len(m.delta.New); n > 0 {
		parts = append(parts, lipgloss.NewStyle().Foreground(s.cHigh).Render(fmt.Sprintf("+ %d new", n)))
	}
	if n := len(m.delta.Changed); n > 0 {
		parts = append(parts, s.bone.Render(fmt.Sprintf("~ %d changed", n)))
	}
	return s.dim.Render("since last scan  ") + strings.Join(parts, s.dim.Render("   "))
}

// axisCell is the rendered width of one axis: a 9-column id, an 8-column
// meter, and a 4-column value. axisGap separates two of them.
const (
	axisCell = 9 + 8 + 4
	axisGap  = 3
)

// axesLine renders the score axes, wrapped to the terminal width.
//
// It used to join every axis into a single row. With nine domains that is
// 9*21 + 8*3 = 213 columns, so on any ordinary 80- or 120-column terminal the
// row was far wider than the screen — and in alt-screen mode a wrapped line
// does not merely look wrong, it pushes every row below it down and off the
// bottom of the frame, taking the findings list with it.
func (m *appModel) axesLine() string {
	s := m.sty()
	var cells []string
	for _, ax := range m.report.Score.Axes {
		label := s.dim.Render(fmt.Sprintf("%-9s", ax.ID))
		switch {
		case !ax.Applicable:
			cells = append(cells, label+s.track.Render(strings.Repeat("░", 8))+s.dim.Render(" N/A"))
		case ax.Degraded:
			// Scored, but from an incomplete picture — the "~" says so, since
			// a bare number here reads as a full result. Padded to the same
			// width as an undegraded value so the columns still line up.
			cells = append(cells, label+s.meter(ax.Score, 8, s.band(ax.Score))+
				s.bone.Render(fmt.Sprintf(" %-3s", strconv.Itoa(int(ax.Score))+"~")))
		default:
			cells = append(cells, label+s.meter(ax.Score, 8, s.band(ax.Score))+s.bone.Render(fmt.Sprintf(" %-3d", ax.Score)))
		}
	}
	if len(cells) == 0 {
		return ""
	}

	// How many cells fit: n cells occupy n*axisCell + (n-1)*axisGap. Always
	// emit at least one per row, so a pathologically narrow terminal still
	// renders something rather than dividing by zero or looping forever.
	perRow := 1
	if m.width > axisCell {
		perRow = (m.width + axisGap) / (axisCell + axisGap)
	}
	if perRow < 1 {
		perRow = 1
	}

	gap := s.dim.Render(strings.Repeat(" ", axisGap))
	var rows []string
	for i := 0; i < len(cells); i += perRow {
		end := min(i+perRow, len(cells))
		rows = append(rows, strings.Join(cells[i:end], gap))
	}
	return strings.Join(rows, "\n")
}

const listHint = "↑/↓ move   enter details   f fix   space select   a fix marked\n" +
	"s severity   d domain   x fixable   c clear   h history   t theme   r rescan   q quit"

func (m *appModel) viewList() string {
	s := m.sty()
	var b strings.Builder
	hdr := m.header()
	b.WriteString(hdr)
	b.WriteString(m.rule() + "\n")

	fl := m.filterLine()

	// Empty list: distinguish a clean host from a too-narrow filter.
	if len(m.active) == 0 {
		if fl != "" {
			b.WriteString(fl + "\n")
			b.WriteString("\n" + s.dim.Render("  No findings match the filter.") + "\n")
		} else {
			b.WriteString("\n" + s.safe.Render("  No problems found. Clean.") + "\n")
		}
		b.WriteString(m.footer("c clear   t theme   r rescan   q quit"))
		return b.String()
	}

	// Measure the header rather than assuming its height. It used to be a
	// constant 8, which silently assumed a two-line header — one brand line
	// and one axes line. That was already one short whenever a delta line was
	// present, and the axes strip now wraps to several rows on a narrow
	// terminal. Reserving too little makes the list draw more rows than fit,
	// pushing the footer and its key hints off the bottom of the frame.
	//
	// The footer is measured too, since its hint now reflows. The remaining
	// 3 is what viewList draws itself: the rule under the header, the count
	// line, and the footer's leading blank.
	ftr := m.footer(listHint)
	reserved := strings.Count(hdr, "\n") + strings.Count(ftr, "\n") + 3
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
	head := s.dim.Render(count)
	if n := len(m.selected); n > 0 {
		head += s.safe.Render(fmt.Sprintf("   ✓ %d marked", n))
	}
	if len(m.active) > visible {
		head += s.dim.Render(fmt.Sprintf("      %d–%d", m.offset+1, end))
	}
	b.WriteString(head + "\n")
	if fl != "" {
		b.WriteString(fl + "\n")
	}

	for i := m.offset; i < end; i++ {
		b.WriteString(m.findingRow(m.active[i], i == m.cursor) + "\n")
	}
	b.WriteString(ftr)
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
	s := m.sty()
	sevC := s.severityColor(f.Severity)
	gutter := lipgloss.NewStyle().Foreground(sevC).Render("▌")
	mark := "  "
	if f.Remediation == model.RemediationAuto {
		if m.selected[f.Key()] {
			mark = s.safe.Render("✓ ")
		} else {
			mark = s.dim.Render("· ")
		}
	}
	sev := sevAbbr(f.Severity)

	// Budget the row from what is actually drawn rather than a fixed 46.
	// The old constant did not account for the trailing service suffix at
	// all, so a finding on "cloud/nextcloud-12" overran the terminal by
	// however long the service name happened to be — and it did not account
	// for an ID longer than its %-13s field either (cve.outdated-image is
	// eighteen). Both are host-supplied, so neither has a safe upper bound.
	const gutterAndMark = 3 // "▌" + a two-column mark
	body := fmt.Sprintf("%-4s %-13s ", sev, f.ID)

	if cursor {
		title := truncate(f.Title, m.width-gutterAndMark-lipgloss.Width(body))
		return gutter + mark + s.sel.Render(padRight(body+title, m.width-gutterAndMark))
	}

	// The suffix is dropped rather than truncated when there is no room for
	// it: a service name cut to "(clo…" identifies nothing, and the title is
	// the more useful of the two.
	suffix := m.serviceSuffix(f)
	avail := m.width - gutterAndMark - lipgloss.Width(body)
	if lipgloss.Width(suffix) > avail {
		suffix = ""
	}
	title := truncate(f.Title, avail-lipgloss.Width(suffix))
	return gutter + mark + lipgloss.NewStyle().Foreground(sevC).Render(sev) +
		s.dim.Render(fmt.Sprintf(" %-13s ", f.ID)) + s.bone.Render(title) + suffix
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
	s := m.sty()
	return s.dim.Render("FILTER  ") + s.bone.Render(strings.Join(parts, " · "))
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

func (m *appModel) serviceSuffix(f model.Finding) string {
	if f.Service == "" {
		return ""
	}
	return m.sty().dim.Render("  (" + f.Service + ")")
}

func (m *appModel) viewDetail() string {
	s := m.sty()
	f := m.active[m.cursor]
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString(m.rule() + "\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(s.severityColor(f.Severity)).Bold(true).Render(strings.ToUpper(f.Severity.String())) +
		"  " + s.brand.Render(f.Title) + "\n")
	meta := strings.ToUpper(f.ID + "  ·  " + f.Remediation.String())
	if f.Service != "" {
		meta += "  ·  SERVICE: " + f.Service
	}
	b.WriteString(s.dim.Render(meta) + "\n\n")
	b.WriteString(s.bone.Render(wrap(f.Description, min(m.width-4, 78))) + "\n\n")
	if f.HowToFix != "" {
		b.WriteString(s.dim.Render("HOW TO FIX") + "\n")
		b.WriteString(s.bone.Render(wrap(f.HowToFix, min(m.width-4, 78))) + "\n")
	}
	hint := "esc back   q list"
	if f.IsFixable() {
		hint = "f apply fix   " + hint
	}
	b.WriteString(m.footer(hint))
	return b.String()
}

func (m *appModel) viewPreview() string {
	s := m.sty()
	var b strings.Builder
	b.WriteString(s.dim.Render("FIX PREVIEW") + "\n")
	b.WriteString(s.brand.Render(m.preview.Label) + "\n")
	b.WriteString(m.rule() + "\n\n")

	if len(m.preview.Actions) > 1 {
		b.WriteString(s.dim.Render("Alternatives (press a number):") + "\n")
		for _, a := range m.preview.Actions {
			marker := "  "
			if a.Index == m.previewAction {
				marker = lipgloss.NewStyle().Foreground(s.cBone).Render("› ")
			}
			b.WriteString(marker + s.bone.Render(fmt.Sprintf("[%d] %s", a.Index, a.Label)) + "\n")
		}
		b.WriteString("\n")
	}

	a := m.preview.Actions[m.previewAction]
	if a.Warning != "" {
		// Wrap the warning. It is the one place the preview explains what
		// cannot be undone, and unwrapped it ran past the terminal edge and
		// was clipped mid-sentence — cut, in the exec case, at "There is no
		// rollback" with the reason that follows lost. The "⚠  " prefix is
		// two columns plus a space, so the continuation lines are indented to
		// sit under the text rather than the marker.
		warn := wrap(a.Warning, min(m.width-4, 78))
		warn = strings.ReplaceAll(warn, "\n", "\n   ")
		b.WriteString(lipgloss.NewStyle().Foreground(s.cHigh).Render("⚠  "+warn) + "\n\n")
	}
	switch a.Type {
	case "edit", "mode":
		b.WriteString(s.renderDiff(a.Diff))
	case "exec":
		b.WriteString(s.dim.Render("These commands will run:") + "\n")
		for _, cmd := range a.Commands {
			b.WriteString(s.dim.Render("  $ "+strings.Join(cmd, " ")) + "\n")
		}
	default:
		// Never leave the apply/cancel footer with an empty body above it.
		b.WriteString(s.dim.Render("(no preview available for action type "+a.Type+")") + "\n")
	}
	b.WriteString(m.footer("y apply   n cancel"))
	return b.String()
}

// viewHistory lists every applied fix, newest first, so a fix applied here
// can be undone here rather than only from the CLI. Non-reversible
// (command) fixes are dimmed: they are part of the record but there is
// nothing file-backed to restore.
func (m *appModel) viewHistory() string {
	s := m.sty()
	var b strings.Builder
	hdr := m.header()
	b.WriteString(hdr)
	b.WriteString(m.rule() + "\n")

	// Measure the header rather than assuming 8 lines. viewList was corrected
	// this way when the axes strip started wrapping; this view had the same
	// hardcoded reservation and the same bug — on a narrow terminal the extra
	// header rows pushed the checkpoint list past the footer. The 6 is the
	// chrome viewHistory draws around the rows (matching viewList): the rule
	// under the header, the count line, and the footer's blank, rule, and two
	// hint lines.
	ftr := m.footer(historyHint)
	reserved := strings.Count(hdr, "\n") + strings.Count(ftr, "\n") + 3
	visible := m.height - reserved
	if visible < 1 {
		visible = 1
	}
	m.cpOffset = scrollOffset(m.cpCursor, len(m.checkpoints), visible, m.cpOffset)
	end := m.cpOffset + visible
	if end > len(m.checkpoints) {
		end = len(m.checkpoints)
	}

	head := s.dim.Render(fmt.Sprintf("APPLIED FIXES · %d", len(m.checkpoints)))
	if len(m.checkpoints) > visible {
		head += s.dim.Render(fmt.Sprintf("      %d–%d", m.cpOffset+1, end))
	}
	b.WriteString(head + "\n")

	for i := m.cpOffset; i < end; i++ {
		b.WriteString(m.checkpointRow(m.checkpoints[i], i == m.cpCursor) + "\n")
	}
	b.WriteString(ftr)
	return b.String()
}

const historyHint = "↑/↓ move   enter roll back   esc back   q list"

func (m *appModel) checkpointRow(cp model.Checkpoint, cursor bool) string {
	s := m.sty()
	when := cp.CreatedAt.Local().Format("01-02 15:04")
	label := truncate(cp.Label, m.width-40)
	line := fmt.Sprintf("%-11s %-15s %s", when, cp.FindingID, label)
	if cursor {
		return s.sel.Render(padRight(line, m.width-1))
	}
	if !cp.Reversible {
		return s.dim.Render(line)
	}
	return s.dim.Render(when+" ") + s.bone.Render(fmt.Sprintf("%-15s ", cp.FindingID)) +
		s.bone.Render(label)
}

const themeHint = "↑/↓ preview   enter keep   esc cancel"

// viewTheme is the color-theme picker. Moving the cursor restyles the whole
// frame on the spot rather than showing a swatch and a name: a palette is
// only judgeable against the meters, severity gutters and diffs it will
// actually be drawn with.
func (m *appModel) viewTheme() string {
	s := m.sty()
	var b strings.Builder
	b.WriteString(s.dim.Render("THEME") + "\n")
	b.WriteString(s.brand.Render(m.th.Name) + "\n")
	b.WriteString(m.rule() + "\n\n")

	all := theme.All()
	// A row is "› " + an 18-column name + a two-space gap + five two-column
	// swatches. The swatch is dropped rather than clipped on a terminal too
	// narrow for it — half a palette says less than none.
	const nameW, swatchW = 18, 10
	showSwatch := m.width >= 2+nameW+2+swatchW
	for i, t := range all {
		marker := "  "
		if i == m.themeCursor {
			marker = lipgloss.NewStyle().Foreground(s.cBone).Render("› ")
		}
		name := padRight(truncate(t.Name, max(1, min(nameW, m.width-2))), nameW)
		row := marker
		if i == m.themeCursor {
			row += s.sel.Render(name)
		} else {
			row += s.bone.Render(name)
		}
		if showSwatch {
			row += "  " + swatch(t)
		}
		b.WriteString(row + "\n")
	}

	b.WriteString("\n" + s.dim.Render(wrap("Colors mean the same thing in every theme: the four severity "+
		"steps and safety. Everything else is chrome.", min(m.width-2, 78))) + "\n")
	b.WriteString(m.footer(themeHint))
	return b.String()
}

// swatch previews the five colors that carry meaning, in that theme's own
// palette rather than the active one.
func swatch(t theme.Theme) string {
	var b strings.Builder
	for _, hex := range []string{t.Palette.Crit, t.Palette.High, t.Palette.Med, t.Palette.Low, t.Palette.Safe} {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(hex)).Render("██"))
	}
	return b.String()
}

// viewRollbackConfirm mirrors viewPreview's y/n gesture, showing the diff
// the rollback would revert so the decision is made on evidence.
func (m *appModel) viewRollbackConfirm() string {
	s := m.sty()
	cp := m.checkpoints[m.cpCursor]
	var b strings.Builder
	b.WriteString(s.dim.Render("ROLL BACK") + "\n")
	b.WriteString(s.brand.Render(cp.Label) + "\n")
	b.WriteString(m.rule() + "\n\n")
	b.WriteString(s.dim.Render("Restores:") + "\n")
	for _, p := range cp.Files {
		b.WriteString(s.bone.Render("  "+p) + "\n")
	}
	b.WriteString("\n")
	if cp.RestartService != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(s.cHigh).
			Render("⚠  You may need to restart '"+cp.RestartService+"' afterwards.") + "\n\n")
	}
	if cp.Diff != "" {
		b.WriteString(s.dim.Render("This change will be reverted:") + "\n")
		b.WriteString(s.renderDiff(cp.Diff))
	}
	b.WriteString(m.footer("y roll back   n cancel"))
	return b.String()
}

func (m *appModel) viewMessage() string {
	s := m.sty()
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString(m.rule() + "\n\n  " + s.bone.Render(m.status) + "\n")
	b.WriteString(m.footer("press any key to continue"))
	return b.String()
}

func (m *appModel) footer(hint string) string {
	return "\n" + m.rule() + "\n" + m.sty().dim.Render(m.wrapHint(hint))
}

// wrapHint reflows a key-binding hint onto as many lines as the terminal
// needs. The hints are written as fixed two-line strings, and the longer of
// the two is 75 columns — wider than a 72-column pane, where it wrapped and
// pushed the frame. Items are separated by three spaces, which is the only
// place a break is legible.
func (m *appModel) wrapHint(hint string) string {
	const sep = "   "
	if m.width <= 0 {
		return hint
	}
	var out []string
	for _, para := range strings.Split(hint, "\n") {
		cur := ""
		for _, item := range strings.Split(para, sep) {
			cand := item
			if cur != "" {
				cand = cur + sep + item
			}
			if lipgloss.Width(cand) > m.width && cur != "" {
				out = append(out, cur)
				cur = item
				continue
			}
			cur = cand
		}
		if cur != "" {
			out = append(out, cur)
		}
	}
	return strings.Join(out, "\n")
}

func (s *styles) renderDiff(diff string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(diff, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			b.WriteString(s.safe.Render(line) + "\n")
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			b.WriteString(lipgloss.NewStyle().Foreground(s.cCrit).Render(line) + "\n")
		default:
			b.WriteString(s.dim.Render(line) + "\n")
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

// truncate shortens s to at most max columns, marking the cut with an
// ellipsis when there is room for one.
//
// The old guard returned s unchanged whenever max < 4, which inverted the
// function exactly where it was needed. findingRow passes m.width-46, so on a
// 40-column terminal max is negative and every title came back at full
// length: a narrower terminal produced longer lines than a wide one, and the
// rows wrapped.
//
// It also sliced by byte, which can cut a multi-byte rune in half and emit a
// replacement character. Findings are English today, but service names and
// file paths come from the host.
func truncate(s string, max int) string {
	r := []rune(s)
	switch {
	case max <= 0:
		return ""
	case len(r) <= max:
		return s
	case max < 4:
		return string(r[:max]) // no room for an ellipsis to be worth a column
	default:
		return string(r[:max-1]) + "…"
	}
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
