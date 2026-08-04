package tui

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/textwidth"

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
	switch model.BandFor(v) {
	case model.BandGood:
		return s.cSafe
	case model.BandFair:
		return s.cMed
	case model.BandPoor:
		return s.cHigh
	default:
		return s.cCrit
	}
}

// meter renders a segmented bar: filled blocks in c, empty in the track.
func (s *styles) meter(pct uint8, width int, c color.Color) string {
	if width < 0 {
		width = 0 // strings.Repeat panics on a negative count
	}
	filled := int(pct) * width / 100
	if filled > width {
		filled = width
	}
	on := lipgloss.NewStyle().Foreground(c).Render(strings.Repeat("█", filled))
	off := s.track.Render(strings.Repeat("░", width-filled))
	return on + off
}

// View draws the whole screen. Every mode goes through compose (see
// frame.go), so all of them are exactly as tall as the terminal, with the key
// hints pinned to the last row.
func (m *appModel) View() tea.View {
	s := m.sty()
	m.fitSize()

	var content string
	switch m.mode {
	case modeScanning:
		content = m.compose(noHeader(), nil, "ctrl+c quit", m.scanningRows)

	case modeList:
		content = m.compose(fullHeader(), nil, m.listHintFor(), m.listRows)

	case modeDetail:
		hint := "e explain (AI)   esc back   q list"
		if len(m.active) > 0 && m.active[m.cursor].IsFixable() {
			hint = "f apply fix   " + hint
		}
		content = m.compose(compactHeader(""), nil, hint,
			func(n int) []string { return m.clipRows(m.detailRows(), n) })

	case modePreview:
		content = m.compose(compactHeader("FIX PREVIEW"),
			[]string{s.brand.Render(m.preview.Label)}, "y apply   n cancel",
			func(n int) []string { return m.clipRows(m.previewRows(), n) })

	case modeMessage:
		content = m.compose(compactHeader(""), nil, "press any key to continue",
			func(n int) []string {
				return centerRows(styledRows(s.bone, "  "+wrap(m.status, min(m.width-4, 78))), n)
			})

	case modeHistory:
		content = m.compose(compactHeader(""), nil, historyHint, m.historyRows)

	case modeRollbackConfirm:
		var title []string
		if len(m.checkpoints) > 0 {
			title = []string{s.brand.Render(m.checkpoints[m.cpCursor].Label)}
		}
		content = m.compose(compactHeader("ROLL BACK"), title, "y roll back   n cancel",
			func(n int) []string { return m.clipRows(m.rollbackRows(), n) })

	case modeForceConfirm:
		content = m.compose(compactHeader("ROLLBACK DECLINED"), nil,
			"y overwrite anyway   any other key cancel",
			func(n int) []string { return m.clipRows(m.forceRows(), n) })

	case modeTheme:
		content = m.compose(compactHeader("THEME"),
			[]string{s.brand.Render(m.th.Name)}, themeHint,
			func(n int) []string { return m.clipRows(m.themeRows(), n) })

	case modeLayout:
		content = m.compose(compactHeader("LAYOUT"),
			[]string{s.brand.Render(m.layoutName())}, layoutHint,
			func(n int) []string { return m.clipRows(m.layoutPickerRows(), n) })
	}

	// Paint the terminal background too. Without it a theme only recolors the
	// text and the terminal's own background shows through every gap, which
	// reads as a broken palette rather than a chosen one. Bubble Tea resets
	// this to the terminal's default when the program exits — note that a
	// terminal whose background was itself set by an earlier escape sequence
	// comes back to its default rather than to that value.
	return tea.View{Content: content, AltScreen: true, BackgroundColor: s.cInk}
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

// axisCell is the rendered width of one axis: a 10-column id, an 8-column
// meter, and a 4-column value. axisGap separates two of them. The id is
// 10 wide, not 9, so the longest ids ("container", "fileperms") keep a
// space before the meter instead of butting straight against it.
const (
	axisCell = 10 + 8 + 4
	axisGap  = 3
)

// axesLine renders the score axes, wrapped to the terminal width.
//
// It used to join every axis into a single row. With nine domains that is
// 9*22 + 8*3 = 222 columns, so on any ordinary 80- or 120-column terminal the
// row was far wider than the screen — and in alt-screen mode a wrapped line
// does not merely look wrong, it pushes every row below it down and off the
// bottom of the frame, taking the findings list with it.
func (m *appModel) axesLine() string {
	s := m.sty()
	var cells []string
	for _, ax := range m.report.Score.Axes {
		label := s.dim.Render(fmt.Sprintf("%-10s", ax.ID))
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
	var out []string
	for i := 0; i < len(cells); i += perRow {
		end := min(i+perRow, len(cells))
		out = append(out, strings.Join(cells[i:end], gap))
	}
	return strings.Join(out, "\n")
}

const (
	listHint = "↑/↓ move   enter details   f fix   space select   a fix marked\n" +
		"s severity   d domain   x fixable   c clear   h history   t theme   l layout   r rescan   q quit"
	emptyListHint = "c clear   t theme   l layout   r rescan   q quit"
	historyHint   = "↑/↓ move   enter roll back   esc back   q list"
	themeHint     = "↑/↓ preview   enter keep   esc cancel"
	// The lanes arrangement adds one key, so it adds one line of hint. Written
	// as its own string rather than appended at the call site because the
	// footer is the only documentation these bindings have.
	laneListHint = "↑/↓ move   enter details   f fix   space select   m mark lane   a fix marked\n" +
		"s severity   d domain   x fixable   c clear   h history   t theme   l layout   r rescan   q quit"
	// Not "preview", which is what the theme picker's says and earns: moving
	// the cursor there restyles the whole frame on the spot. Here there is
	// nothing to preview, because the picker screen is not one of the
	// arrangements — enter is what shows you the choice.
	layoutHint = "↑/↓ choose   enter apply   esc cancel"
)

// listHintFor picks the footer for the active arrangement.
func (m *appModel) listHintFor() string {
	if len(m.active) == 0 {
		return emptyListHint
	}
	if m.wantsLanes() {
		return laneListHint
	}
	return listHint
}

// scanningRows is the whole scan screen: one status line, held in the middle
// of an otherwise empty frame.
func (m *appModel) scanningRows(n int) []string {
	return centerRows(styledRows(m.sty().dim, "  "+m.status), n)
}

// minVerdictBody is how many rows must remain for the verdict band to be
// worth its four. A sentence about the list, above no list, is not a summary.
const minVerdictBody = 4

// minInlineList is how many findings must stay visible around an opened one.
// Below that the inline block has stopped being a finding opened in a list
// and become the detail view with a row of context.
const minInlineList = 3

// listRows draws the body of the findings screen: the verdict band across
// the top where an arrangement asks for one, then the rail, the list and the
// detail pane side by side.
//
// It is the only place the arrangements meet. Everything below it is written
// against a column width rather than the terminal width, which is what lets
// the same list render at 120 columns and at 46 without a second code path.
func (m *appModel) listRows(budget int) []string {
	if budget <= 0 {
		return nil
	}
	railW, listW, paneW := m.bodyColumns()

	// The band spans every column, because in the dashboard it is a sibling
	// of <main> rather than a cell inside it.
	var lead []string
	if m.wantsVerdict() {
		if v := m.verdictRows(m.width); len(v)+minVerdictBody <= budget {
			lead = v
		}
	}
	inner := budget - len(lead)

	list := m.listColumn(inner, listW)
	if railW == 0 && paneW == 0 {
		return append(lead, fitRows(list, inner)...)
	}

	widths := make([]int, 0, 3)
	cols := make([][]string, 0, 3)
	if railW > 0 {
		widths = append(widths, railW)
		cols = append(cols, m.railRows(railW, inner))
	}
	widths = append(widths, listW)
	cols = append(cols, list)
	if paneW > 0 {
		widths = append(widths, paneW)
		cols = append(cols, m.paneRows(paneW, inner))
	}
	return append(lead, m.joinColumns(inner, widths, cols)...)
}

// paneRows is the detail column: the finding under the cursor, in full.
//
// The dashboard's pane shows an overview until something is clicked and the
// finding after that. A terminal has no "nothing selected" state — the
// cursor is always on a row — so the pane follows it, which is the closer
// translation of what the pane is for: reading the finding without leaving
// the list.
func (m *appModel) paneRows(w, budget int) []string {
	s := m.sty()
	if budget <= 0 {
		return nil
	}
	if len(m.active) == 0 {
		return centerRows([]string{s.dim.Render(truncate("Nothing to show.", w))}, budget)
	}
	body := m.detailBodyRows(m.active[m.cursor], min(w-2, 78))
	out := make([]string, 0, len(body))
	for _, r := range body {
		out = append(out, " "+r)
	}
	return m.clipRows(out, budget)
}

// listColumn draws the findings list into the rows and the columns it was
// given. The head and filter lines are drawn from that same budget rather
// than reserved outside it, so there is exactly one place the arithmetic
// happens.
func (m *appModel) listColumn(budget, w int) []string {
	s := m.sty()
	if budget <= 0 {
		return nil
	}

	fl := m.chipRow()

	// Empty list: distinguish a clean host from a too-narrow filter — and,
	// when nothing is filtered, a clean host from one that could not be
	// examined. "Clean" is a claim about the whole host, so it may only be
	// made when the whole host was looked at. The CLI has always drawn that
	// line; this view and the dashboard both said "Clean." unconditionally,
	// so a host whose every checker failed read as spotless in two
	// interfaces out of three.
	//
	// The message has to stand on its own here. The CLI can say "see above"
	// because it prints a per-domain status block first; this view prints
	// none, so it names the count itself.
	if len(m.active) == 0 {
		var body []string
		switch {
		case m.filterActive():
			// Asked explicitly rather than inferred from the chip row: the
			// chips are drawn from the unfiltered report, so they are there
			// whenever the host has findings at all, filtered or not.
			body = append(body, fl, "", s.dim.Render("  No findings match the filter."))
		case m.report.IncompleteDomains() > 0:
			// Wrapped, for the reason the preview's warning is wrapped: this
			// row is far longer than the "Clean." it replaces, and clipped at
			// the terminal edge it degrades into "No problems found in the
			// domains that" — which reads as the very claim it exists to
			// withhold.
			warn := lipgloss.NewStyle().Foreground(s.cHigh)
			msg := fmt.Sprintf("No problems found in the domains that ran — but %d did not complete.",
				m.report.IncompleteDomains())
			for _, l := range strings.Split(wrap(msg, min(w-4, 78)), "\n") {
				body = append(body, warn.Render("  "+l))
			}
		default:
			body = append(body, s.safe.Render("  No problems found. Clean."))
		}
		return centerRows(body, budget)
	}

	chrome := 1
	if fl != "" {
		chrome = 2
	}
	visible := budget - chrome
	if visible < 1 {
		// Findings beat labels: on a frame this short the list itself is the
		// only thing worth drawing.
		chrome, visible = 0, budget
	} else if chrome == 2 && visible < minChipRows {
		// The chips are a summary of the list, and a summary that costs half
		// of what it summarises is not worth its row.
		chrome, visible = 1, budget-1
	}

	// The inline block is paid for out of the list's own rows rather than
	// added under them, so the column is still exactly `budget` tall and the
	// footer does not move when a finding is opened.
	var inline []string
	if m.wantsInline() {
		if in := m.inlineRows(w); len(in) > 0 && visible-len(in) >= minInlineList {
			inline, visible = in, visible-len(in)
		}
	}

	var out []string
	head := func(shownFrom, shownTo, total int) {
		if chrome == 0 {
			return
		}
		count := fmt.Sprintf("FINDINGS · %d", len(m.active))
		if t := m.activeTotal(); t != len(m.active) {
			count = fmt.Sprintf("FINDINGS · %d/%d", len(m.active), t)
		}
		h := s.dim.Render(count)
		if n := len(m.selected); n > 0 {
			h += s.safe.Render(fmt.Sprintf("   ✓ %d marked", n))
		}
		if total > visible {
			h += s.dim.Render(fmt.Sprintf("      %d–%d", shownFrom, shownTo))
		}
		out = append(out, h)
		if chrome == 2 {
			out = append(out, fl)
		}
	}

	// Lanes scrolls over the rendered rows rather than over the findings,
	// because the lane headers are rows too: a window computed on finding
	// indices would scroll the list out from under its own headings.
	if m.wantsLanes() {
		rows, cursorRow := m.laneRows(w)
		m.rowOffset = scrollOffset(cursorRow, len(rows), visible, m.rowOffset)
		end := min(m.rowOffset+visible, len(rows))
		head(m.rowOffset+1, end, len(rows))
		return append(out, rows[m.rowOffset:end]...)
	}

	m.offset = scrollOffset(m.cursor, len(m.active), visible, m.offset)
	end := min(m.offset+visible, len(m.active))
	head(m.offset+1, end, len(m.active))
	for i := m.offset; i < end; i++ {
		out = append(out, m.findingRow(m.active[i], i == m.cursor, w))
		if i == m.cursor {
			out = append(out, inline...)
		}
	}
	return out
}

// laneRows renders the list grouped into one section per severity, and
// returns the row index the cursor landed on so the caller can scroll to it.
//
// A severity with nothing at it gets no lane: a "CRITICAL · 0" heading is a
// row of screen spent announcing that nothing happened, and four of them on
// a nearly-clean host is the whole list.
func (m *appModel) laneRows(w int) ([]string, int) {
	var rows []string
	cursorRow := 0
	for _, sev := range model.AllSeverities() {
		var idx []int
		autos := 0
		for i, f := range m.active {
			if f.Severity != sev {
				continue
			}
			idx = append(idx, i)
			if f.Remediation == model.RemediationAuto {
				autos++
			}
		}
		if len(idx) == 0 {
			continue
		}
		rows = append(rows, m.laneHeadRow(sev, len(idx), autos, w))
		for _, i := range idx {
			if i == m.cursor {
				cursorRow = len(rows)
			}
			rows = append(rows, m.findingRow(m.active[i], i == m.cursor, w))
		}
	}
	return rows, cursorRow
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
//
// w is the column the row is drawn into, which is the terminal width only in
// the arrangements that give the list the whole screen. Passing it beats
// reading m.width: the rail and the detail pane are real columns, and a row
// budgeted against the terminal would overrun its own column and push every
// column right of it off the screen.
func (m *appModel) findingRow(f model.Finding, cursor bool, w int) string {
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
		title := truncate(f.Title, w-gutterAndMark-lipgloss.Width(body))
		return gutter + mark + s.sel.Render(padRight(body+title, w-gutterAndMark))
	}

	// The suffix is dropped rather than truncated when there is no room for
	// it: a service name cut to "(clo…" identifies nothing, and the title is
	// the more useful of the two.
	//
	// It is also dropped when keeping it would starve the title, which is a
	// second thing entirely and only became visible when the list stopped
	// being the width of the terminal. In a narrow column the suffix fits and
	// the title does not, so the row came out as "agent.auth-disabled O
	// (openclaw@root)" — the service named in full beside a single letter of
	// the problem. The service qualifies the title; a title with nothing left
	// of it has nothing to qualify.
	const minTitleWidth = 16
	suffix := m.serviceSuffix(f)
	avail := w - gutterAndMark - lipgloss.Width(body)
	if sw := lipgloss.Width(suffix); sw > avail || avail-sw < minTitleWidth {
		suffix = ""
	}
	title := truncate(f.Title, avail-lipgloss.Width(suffix))
	return gutter + mark + lipgloss.NewStyle().Foreground(sevC).Render(sev) +
		s.dim.Render(fmt.Sprintf(" %-13s ", f.ID)) + s.bone.Render(title) + suffix
}

// sourceLabel is the short domain name shown in the filter line.
//
// The table it used to hold now lives on model.Source, because the
// dashboard kept an independent copy of the same nine entries and both
// went stale together when the sysctl domain landed. One table, two
// readers. The empty-label fallback is for a domain added without one —
// an ugly name beats a blank filter line that says nothing is filtered.
func sourceLabel(s model.Source) string {
	if l := s.Label(); l != "" {
		return l
	}
	return s.String()
}

// chipRow is the dashboard's filter bar, in one row.
//
// It replaces a line that appeared only while a filter was set and named
// what it was. That told the user what they had just pressed and nothing
// else: the shape of the report — how much of a wall of findings is
// Critical, how much of it hostveil can fix on its own — was reachable only
// by scrolling and counting, in the one interface where scrolling is most
// expensive. The dashboard has never made anyone do that, and this is its
// chip bar: a count per severity, the fixable count, and the active filter
// picked out on the chip it belongs to.
//
// The counts are taken over the *unfiltered* set, as the dashboard's are.
// Counts that moved with the filter would be describing the filter rather
// than the host, and the number a narrowed list most needs beside it is what
// it was narrowed from.
//
// The severity threshold is a range, not a selection, so every chip at or
// above it reads as active — anything else would show CRIT dim on a list
// that is showing exactly the Criticals.
func (m *appModel) chipRow() string {
	s := m.sty()
	unfiltered := m.report.Select(model.Filter{})

	counts := map[model.Severity]int{}
	fixable := 0
	for _, f := range unfiltered {
		counts[f.Severity]++
		if f.IsFixable() {
			fixable++
		}
	}

	var chips []string
	for _, sev := range model.AllSeverities() {
		n := counts[sev]
		if n == 0 {
			continue // the dashboard omits a severity nothing is at, too
		}
		on := m.filter.MinSeverity != nil && sev <= *m.filter.MinSeverity
		chips = append(chips, m.chip(fmt.Sprintf("%s %d", sevAbbr(sev), n), on, s.severityColor(sev)))
	}
	if fixable > 0 {
		// Safe rather than the dashboard's slate. "Fixable" is a claim about
		// safety, which is the one thing besides risk this design system lets
		// a color mean, and spending it here is what makes the count read as
		// the good news it is.
		chips = append(chips, m.chip(fmt.Sprintf("FIXABLE %d", fixable), m.filter.FixableOnly, s.cSafe))
	}
	if m.filter.Source != model.SourceUnset {
		chips = append(chips, m.chip(strings.ToUpper(sourceLabel(m.filter.Source)), true, s.cSlate))
	}
	if len(chips) == 0 {
		return ""
	}
	return strings.Join(chips, "  ")
}

// chip draws one filter chip the way the dashboard's stylesheet does: the
// chip's own color on the page while it is merely available, and filled —
// ink on that color — while it is on.
//
// The fill is an attribute, so it does not survive being stripped of
// styling, and it is deliberately not the only thing carrying the state:
// the head line above prints the narrowed count over the unnarrowed one
// ("FINDINGS · 3/26"), which is what a monochrome terminal, a pipe and a
// screenshot all still show.
func (m *appModel) chip(label string, on bool, c color.Color) string {
	if on {
		return lipgloss.NewStyle().Foreground(m.sty().cInk).Background(c).Bold(true).Render(" " + label + " ")
	}
	return lipgloss.NewStyle().Foreground(c).Render(" " + label + " ")
}

// coverageRows names the domains that did not fully cover their ground, with
// the reason each gave.
//
// The axes strip already marks them — "N/A" for a domain that did not run,
// a "~" on a degraded score — but a mark is not an answer. It says a number
// is missing without saying whether the host has no Docker, or the daemon
// refused, or the scan ran as a user who cannot read the socket, which are
// the difference between "nothing to see" and "look again with sudo". The
// CLI has printed these since the states existed and the dashboard shows
// them above the fold; this view showed them nowhere.
//
// One row per notice, most severe state first, so a run that is capped or
// shed keeps the alarming ones and drops the routine ones. Reasons are
// truncated with an ellipsis rather than left for the frame to cut at the
// terminal edge: a sentence that stops mid-word reads as a rendering fault,
// and one that stops at "…" reads as a sentence with more to it — which the
// CLI will print in full.
func (m *appModel) coverageRows() []string {
	s := m.sty()
	warn := lipgloss.NewStyle().Foreground(s.cHigh)
	fail := lipgloss.NewStyle().Foreground(s.cCrit)

	var errored, degraded, skipped []string
	for _, d := range m.report.Domains {
		name := sourceLabel(d.Source)
		switch d.State {
		case model.ScanError:
			errored = append(errored, fail.Render(m.notice("!", name, "failed", d.Reason, "unknown error")))
		case model.ScanDegraded:
			degraded = append(degraded, warn.Render(m.notice("~", name, "partial", d.Reason, "covered only part of the domain")))
		case model.ScanSkipped:
			skipped = append(skipped, s.dim.Render(m.notice("·", name, "skipped", d.Reason, "did not run")))
		}
	}

	rows := append(append(errored, degraded...), skipped...)
	// A host with no Docker, no Trivy and no systemd contributes four of
	// these, and one that could scan nothing at all would contribute twelve —
	// a header taller than the list it is heading. The frame's own fallback
	// bounds that (it drops the whole region rather than squeezing the body),
	// but dropping every notice because there are many is the wrong end to
	// give way at: the first ones are the ones a reader acts on.
	if len(rows) > maxCoverageRows {
		hidden := len(rows) - (maxCoverageRows - 1)
		rows = rows[:maxCoverageRows-1]
		rows = append(rows, s.dim.Render(fmt.Sprintf("· %d more domain(s) did not fully run — hostveil scan lists them", hidden)))
	}
	return rows
}

// maxCoverageRows caps the coverage region so a badly-covered host cannot
// push the findings list off the screen with explanations of its own gaps.
const maxCoverageRows = 3

func (m *appModel) notice(marker, name, state, reason, fallback string) string {
	head := fmt.Sprintf("%s %s %s: ", marker, name, state)
	// -1 keeps a column in hand: the frame clips every row to the width, and
	// a notice that lands exactly on it would have nowhere to show it was cut.
	return head + truncate(reasonOr(reason, fallback), m.width-lipgloss.Width(head)-1)
}

// filterActive reports whether the list is narrowed. The chip row shows the
// filter's *state*, so it cannot answer this — it is drawn either way.
func (m *appModel) filterActive() bool {
	return m.filter.MinSeverity != nil || m.filter.Source != model.SourceUnset || m.filter.FixableOnly
}

func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}

// sevAbbr upper-cases the model's abbreviation rather than keeping a
// second table of its own. The abbreviations are pinned to four characters
// there, which is the width findingRow pads this column to.
func sevAbbr(s model.Severity) string {
	return strings.ToUpper(s.Abbr())
}

func (m *appModel) serviceSuffix(f model.Finding) string {
	if f.Service == "" {
		return ""
	}
	return m.sty().dim.Render("  (" + f.Service + ")")
}

func (m *appModel) detailRows() []string {
	if len(m.active) == 0 {
		return nil
	}
	return append([]string{""}, m.detailBodyRows(m.active[m.cursor], min(m.width-4, 78))...)
}

// detailBodyRows is one finding written out, wrapped to w.
//
// It takes the finding and the width rather than reading the cursor and
// m.width because three things now render it: the full-screen detail view,
// the detail pane beside the list, and the block that opens inline under a
// row. They differ in how much room they have and in nothing else, and a
// second copy of this text is a second place for the AI box to be forgotten.
func (m *appModel) detailBodyRows(f model.Finding, w int) []string {
	s := m.sty()
	out := []string{
		lipgloss.NewStyle().Foreground(s.severityColor(f.Severity)).Bold(true).Render(strings.ToUpper(f.Severity.String())) +
			"  " + s.brand.Render(truncate(f.Title, max(1, w-lipgloss.Width(f.Severity.String())-2)))}
	meta := strings.ToUpper(f.ID + "  ·  " + f.Remediation.String())
	if f.Service != "" {
		meta += "  ·  SERVICE: " + f.Service
	}
	out = append(out, s.dim.Render(truncate(meta, w)), "")
	out = append(out, styledRows(s.bone, wrap(f.Description, w))...)
	if f.HowToFix != "" {
		out = append(out, "", s.dim.Render("HOW TO FIX"))
		out = append(out, styledRows(s.bone, wrap(f.HowToFix, w))...)
	}
	if m.aiBusy || m.aiText != "" || m.aiErr != "" {
		out = append(out, "", s.dim.Render("AI EXPLANATION (ADVISORY)"))
		switch {
		case m.aiBusy:
			out = append(out, s.dim.Render("  asking the local AI model…"))
		case m.aiText != "":
			out = append(out, styledRows(s.bone, wrap(m.aiText, w))...)
		default:
			out = append(out, styledRows(s.dim, wrap(m.aiErr, w))...)
		}
	}
	return out
}

func (m *appModel) previewRows() []string {
	if len(m.preview.Actions) == 0 {
		return nil
	}
	s := m.sty()
	idx := clamp(m.previewAction, 0, len(m.preview.Actions)-1)

	out := []string{""}
	if len(m.preview.Actions) > 1 {
		out = append(out, s.dim.Render("Alternatives (press a number):"))
		for _, a := range m.preview.Actions {
			marker := "  "
			if a.Index == idx {
				marker = lipgloss.NewStyle().Foreground(s.cBone).Render("› ")
			}
			out = append(out, marker+s.bone.Render(fmt.Sprintf("[%d] %s", a.Index, a.Label)))
		}
		out = append(out, "")
	}

	a := m.preview.Actions[idx]
	if a.Warning != "" {
		// Wrap the warning. It is the one place the preview explains what
		// cannot be undone, and unwrapped it ran past the terminal edge and
		// was clipped mid-sentence — cut, in the exec case, at "There is no
		// rollback" with the reason that follows lost. The "⚠  " prefix is
		// two columns plus a space, so the continuation lines are indented to
		// sit under the text rather than the marker.
		warn := lipgloss.NewStyle().Foreground(s.cHigh)
		for i, l := range strings.Split(wrap(a.Warning, min(m.width-4, 78)), "\n") {
			if i == 0 {
				out = append(out, warn.Render("⚠  "+l))
			} else {
				out = append(out, warn.Render("   "+l))
			}
		}
		out = append(out, "")
	}

	switch a.Type {
	case "edit", "mode":
		out = append(out, s.diffRows(a.Diff)...)
	case "exec":
		out = append(out, s.dim.Render("These commands will run:"))
		for _, cmd := range a.Commands {
			out = append(out, s.dim.Render("  $ "+strings.Join(cmd, " ")))
		}
	default:
		// Never leave the apply/cancel footer with an empty body above it.
		out = append(out, s.dim.Render("(no preview available for action type "+a.Type+")"))
	}
	return out
}

// historyRows lists every applied fix, newest first, so a fix applied here
// can be undone here rather than only from the CLI. Non-reversible
// (command) fixes are dimmed: they are part of the record but there is
// nothing file-backed to restore.
func (m *appModel) historyRows(budget int) []string {
	s := m.sty()
	if budget <= 0 || len(m.checkpoints) == 0 {
		return nil
	}

	// The warning costs a row, and it is worth one: a checkpoint missing from
	// this list cannot be rolled back at all, which the list itself cannot
	// say. It is dropped before the header when the terminal is too short,
	// because a list with no header is still a list.
	warn := ""
	if m.historyWarning != "" {
		warn = lipgloss.NewStyle().Foreground(s.cHigh).
			Render("⚠ " + truncate(m.historyWarning, max(1, m.width-2)))
	}

	// The trend costs a row and answers the question the checkpoint list
	// cannot: the list says what was changed, this says whether it helped.
	// Dropped before the warning when the terminal is short, because a
	// missing checkpoint is more urgent than a shape.
	trend := m.trendLine()

	// Chrome is the header, plus the trend and the warning when there is
	// room. They are shed in that order as the terminal shrinks: a shape is
	// the first thing to lose, then the warning, and the header last —
	// a list with no header is still a list.
	chrome := 1
	if warn != "" {
		chrome++
	}
	if trend != "" {
		chrome++
	}
	visible := budget - chrome
	for visible < 1 && chrome > 0 {
		chrome--
		switch {
		case trend != "":
			trend = ""
		case warn != "":
			warn = ""
		}
		visible = budget - chrome
	}

	m.cpOffset = scrollOffset(m.cpCursor, len(m.checkpoints), visible, m.cpOffset)
	end := min(m.cpOffset+visible, len(m.checkpoints))

	var out []string
	if warn != "" {
		out = append(out, warn)
	}
	if trend != "" {
		out = append(out, trend)
	}
	if chrome > 0 {
		head := s.dim.Render(fmt.Sprintf("APPLIED FIXES · %d", len(m.checkpoints)))
		if len(m.checkpoints) > visible {
			head += s.dim.Render(fmt.Sprintf("      %d–%d", m.cpOffset+1, end))
		}
		out = append(out, head)
	}
	for i := m.cpOffset; i < end; i++ {
		out = append(out, m.checkpointRow(m.checkpoints[i], i == m.cpCursor))
	}
	return out
}

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

// themeRows is the color-theme picker. Moving the cursor restyles the whole
// frame on the spot rather than showing a swatch and a name: a palette is
// only judgeable against the meters, severity gutters and diffs it will
// actually be drawn with.
func (m *appModel) themeRows() []string {
	s := m.sty()
	out := []string{""}

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
		out = append(out, row)
	}

	out = append(out, "")
	out = append(out, styledRows(s.dim, wrap("Colors mean the same thing in every theme: the four severity "+
		"steps and safety. Everything else is chrome.", min(m.width-2, 78)))...)
	return out
}

// layoutName is the active arrangement's display name, for the picker's
// title row.
func (m *appModel) layoutName() string {
	l, _ := LookupLayout(m.layoutID())
	return l.Name
}

// layoutPickerRows is the temporary arrangement picker.
//
// Like the theme picker, moving the cursor applies the choice on the spot
// rather than describing it — but unlike a palette, an arrangement cannot be
// judged from the picker screen, because the picker screen is not one of the
// arrangements. So this one carries the note as well: the sentence says what
// bet the layout makes, and pressing enter returns to the list drawn that
// way.
func (m *appModel) layoutPickerRows() []string {
	s := m.sty()
	out := []string{""}

	all := Layouts()
	const nameW = 20
	for i, l := range all {
		marker := "  "
		if i == m.layoutCursor {
			marker = lipgloss.NewStyle().Foreground(s.cBone).Render("› ")
		}
		name := padRight(truncate(l.Name, max(1, min(nameW, m.width-2))), nameW)
		row := marker
		if i == m.layoutCursor {
			row += s.sel.Render(name)
		} else {
			row += s.bone.Render(name)
		}
		out = append(out, row)
	}

	out = append(out, "")
	if m.layoutCursor >= 0 && m.layoutCursor < len(all) {
		out = append(out, styledRows(s.dim, wrap(all[m.layoutCursor].Note, min(m.width-2, 78)))...)
	}
	out = append(out, "", s.dim.Render("Temporary: six arrangements are shipped so one can be chosen. The"))
	out = append(out, s.dim.Render("dashboard carries the same six under the same letters."))
	return out
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

// rollbackRows mirrors previewRows' y/n gesture, showing the diff the
// rollback would revert so the decision is made on evidence.
func (m *appModel) rollbackRows() []string {
	if len(m.checkpoints) == 0 {
		return nil
	}
	s := m.sty()
	cp := m.checkpoints[m.cpCursor]

	out := []string{"", s.dim.Render("Restores:")}
	for _, p := range cp.Files {
		out = append(out, s.bone.Render("  "+p))
	}
	out = append(out, "")
	if cp.RestartService != "" {
		out = append(out, lipgloss.NewStyle().Foreground(s.cHigh).
			Render("⚠  You may need to restart '"+cp.RestartService+"' afterwards."), "")
	}
	if cp.Diff != "" {
		out = append(out, s.dim.Render("This change will be reverted:"))
		out = append(out, s.diffRows(cp.Diff)...)
	}
	return out
}

// forceRows explains a declined rollback and what forcing it costs.
//
// It says the two things the CLI's --force text says, because they are the
// two the operator cannot recover from not knowing: the file has changed
// since hostveil wrote it, and rollback keeps no backup of its own, so
// whatever is in it now is gone for good.
func (m *appModel) forceRows() []string {
	s := m.sty()
	out := []string{""}
	out = append(out, styledRows(lipgloss.NewStyle().Foreground(s.cHigh),
		wrap(m.status, min(m.width-4, 78)))...)
	out = append(out, "")
	out = append(out, styledRows(s.bone, wrap(
		"Forcing the rollback restores hostveil's backup over the current file, discarding those changes. Rollback writes no checkpoint of its own, so this cannot be undone.",
		min(m.width-4, 78)))...)
	if len(m.checkpoints) > 0 {
		cp := m.checkpoints[m.cpCursor]
		out = append(out, "", s.dim.Render("Would overwrite:"))
		for _, p := range cp.Files {
			out = append(out, s.bone.Render("  "+p))
		}
	}
	return out
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

func (s *styles) diffRows(diff string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimRight(diff, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			out = append(out, s.safe.Render(line))
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			out = append(out, lipgloss.NewStyle().Foreground(s.cCrit).Render(line))
		default:
			out = append(out, s.dim.Render(line))
		}
	}
	return out
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
// It is for plain text, before it is styled: it measures runes, so an ANSI
// escape would cost it a dozen columns and it would happily cut through the
// middle of one. Bounding a row that is already styled is clip()'s job.
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
// truncate fits s into max display columns.
//
// It used to count runes, which is right for ASCII and wrong for anything
// wider: a Hangul or CJK cell handed a 20-column budget came back 34
// columns and pushed the row past the edge of the terminal. padRight, three
// lines below, has always measured columns — so the two disagreed about the
// same row.
func truncate(s string, max int) string { return textwidth.Truncate(s, max) }

func padRight(s string, n int) string {
	if lipgloss.Width(s) >= n || n < 0 {
		return s
	}
	return s + strings.Repeat(" ", n-lipgloss.Width(s))
}

// minWrapWidth is the floor wrap applies to a computed width. A narrow
// terminal can drive the budget to nothing, and one word per line is
// unreadable in a way an overrun is not.
const minWrapWidth = 8

// wrap reflows s to width display columns.
//
// It used to count bytes, so Hangul wrapped at roughly two-thirds of the
// width it was given — 24 columns used of 40. `explain --ai` renders
// whatever the local model wrote, which is the path that reaches this with
// text the byte count is wrong about.
func wrap(s string, width int) string { return textwidth.Wrap(s, width, minWrapWidth, "") }

// trendLine renders the score of every retained scan as one row.
//
// It is on the history screen because it answers the other half of the same
// question: the checkpoint list says what was changed, this says whether it
// helped. "Since last scan" already sits on the findings list and answers
// only about the most recent round.
//
// Nothing is drawn for a single scan — a sparkline of one point is a shape
// with no information in it, and a first run should not be handed a chart
// that implies a history it does not have.
func (m *appModel) trendLine() string {
	if len(m.trend) < 2 {
		return ""
	}
	s := m.sty()

	// The most recent scans, not the oldest, when the terminal cannot hold
	// them all. The label and the two scores cost about 24 columns.
	points := m.trend
	if room := m.width - 26; room > 0 && len(points) > room {
		points = points[len(points)-room:]
	}

	first, last := "N/A", "N/A"
	if p := points[0]; p.Applicable {
		first = strconv.Itoa(int(p.Overall))
	}
	if p := points[len(points)-1]; p.Applicable {
		last = strconv.Itoa(int(p.Overall))
	}

	spark := model.Sparkline(points)
	if p := points[len(points)-1]; p.Applicable {
		spark = lipgloss.NewStyle().Foreground(s.band(p.Overall)).Render(spark)
	} else {
		spark = s.dim.Render(spark)
	}
	return s.dim.Render("score  "+first+" ") + spark + s.dim.Render(" "+last)
}
