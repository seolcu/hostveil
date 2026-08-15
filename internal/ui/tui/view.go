package tui

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/textwidth"

	"github.com/seolcu/hostveil/internal/glyph"
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
	cInk    color.Color
	cLine   color.Color
	cBone   color.Color
	cSlate  color.Color
	cCrit   color.Color
	cHigh   color.Color
	cMed    color.Color
	cLow    color.Color
	cSafe   color.Color
	cAccent color.Color

	bone  lipgloss.Style
	dim   lipgloss.Style
	safe  lipgloss.Style
	brand lipgloss.Style
	sel   lipgloss.Style
	track lipgloss.Style
	// accent draws structure: which panel this is, where the cursor is, and
	// which key does the thing. Never risk — the heats own that, and a header
	// that borrowed one would be claiming the panel is dangerous.
	accent lipgloss.Style
}

func newStyles(t theme.Theme) *styles {
	p := t.Palette
	s := &styles{
		cInk:    lipgloss.Color(p.Ink),
		cLine:   lipgloss.Color(p.Line2),
		cBone:   lipgloss.Color(p.Bone),
		cSlate:  lipgloss.Color(p.Slate),
		cCrit:   lipgloss.Color(p.Crit),
		cHigh:   lipgloss.Color(p.High),
		cMed:    lipgloss.Color(p.Med),
		cLow:    lipgloss.Color(p.Low),
		cSafe:   lipgloss.Color(p.Safe),
		cAccent: lipgloss.Color(p.Accent),
	}
	s.accent = lipgloss.NewStyle().Foreground(s.cAccent)
	s.bone = lipgloss.NewStyle().Foreground(s.cBone)
	s.dim = lipgloss.NewStyle().Foreground(s.cSlate)
	s.safe = lipgloss.NewStyle().Foreground(s.cSafe)
	s.brand = lipgloss.NewStyle().Foreground(s.cBone).Bold(true)
	s.sel = lipgloss.NewStyle().Foreground(s.cBone).Background(s.cLine).Bold(true)
	s.track = lipgloss.NewStyle().Foreground(s.cLine)
	return s
}

// kindStyle colors the remediation column.
//
// Deliberately not a heat. The severity column two fields to the left is
// already drawn in crit/high/med/low, and painting the kind in one of those
// too would put two differently-meaning colours from the same set on one row —
// a HIGH row whose kind came out yellow reads as a row that is somehow both.
//
// So: safe for Auto, which is the same green the pick marker already spends on
// the same claim; accent for Review, which is the colour this TUI uses for
// "there is a key here that does something"; and the muted grey for the three
// kinds that offer no button at all, which is what the grey means everywhere
// else on the screen.
func (s *styles) kindStyle(f model.Finding) lipgloss.Style {
	// Pending is drawn in the accent rather than the safe green, and the
	// distinction is the point: green on this column has meant "hostveil can
	// deal with this" since the column existed, and a row whose fix is
	// written but not in force is not dealt with. The accent is what this
	// interface spends on "there is something for you here", which is exactly
	// what is true — the something is a restart.
	if f.Pending {
		return s.accent
	}
	switch f.Remediation {
	case model.RemediationAuto:
		return s.safe
	case model.RemediationReview:
		return s.accent
	default:
		return s.dim
	}
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

// severityColor is the heat a severity is drawn in. cHigh is not used here:
// the palette's four heats serve the *score bands*, and only three of them
// carry a severity now that the top two levels are one.
func (s *styles) severityColor(sev model.Severity) color.Color {
	switch sev {
	case model.SeverityHigh:
		return s.cCrit
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

// meterAtLeastOne is meter, except that a domain which ran always colors at
// least one cell.
//
// The rail's meters fill by score, so the domains in the worst shape drew the
// least ink: on a real host, Container at 0, Dockerd at 10 and CVEs at 16
// filled nothing of six cells while the two clean domains filled all six in
// green. Scanning the rail, the eye landed on what was fine. Worse, an empty
// track is what a *skipped* domain is drawn as deliberately — so the two
// states the whole scanner exists to keep apart, "nothing there" and "I could
// not look", arrived as the same row.
//
// One cell is enough to separate them and does not overstate the score: the
// number beside it carries the value, and it is now drawn in the same band
// color.
func (s *styles) meterAtLeastOne(pct uint8, width int, c color.Color, ran bool) string {
	if ran && width > 0 && int(pct)*width/100 == 0 {
		//nolint:gosec // G115: min(100, …) bounds it before the conversion
		pct = uint8(min(100, (100+width-1)/width))
	}
	return s.meter(pct, width, c)
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
		content = m.compose(compactHeader(""), nil, "press any key to continue", m.messageRows)

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
		parts = append(parts, s.safe.Render(fmt.Sprintf("%s %d resolved", m.gl.Of(glyph.OK), n)))
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
// meter, and the value with a space in front of it. axisGap separates two of
// them. The id is 10 wide, not 9, so the longest ids ("container",
// "fileperms") keep a space before the meter instead of butting straight
// against it.
//
// The value's width comes from model rather than being written down here.
// It was a hand-picked 4 — one space and three columns, which is what a score
// looks like — and the case that needs five is a degraded axis scoring 100.
// See model.ValueTextWidth for what the missing column cost.
const (
	axisCell = 10 + 8 + 1 + model.ValueTextWidth
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
		// The text is model's decision — N/A, a number, or a number with the
		// "~" that keeps a partial result from reading as a clean one. What
		// is decided here is only how it is drawn: an empty track for an axis
		// that did not run, a meter for one that did, and a fixed width so
		// the columns line up whichever it is.
		value := fmt.Sprintf(" %-*s", model.ValueTextWidth, ax.ValueText())
		if !ax.Applicable {
			cells = append(cells, label+s.track.Render(strings.Repeat("░", 8))+s.dim.Render(value))
			continue
		}
		cells = append(cells, label+s.meter(ax.Score, 8, s.band(ax.Score))+s.bone.Render(value))
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
	// Spread them evenly over the rows they need. Packing greedily put twelve
	// domains on a 180-column terminal as seven and then five, which leaves a
	// third of the second row empty and reads as a strip that ran out — the
	// dashboard's grid gives every card the same share and wraps to six and
	// six. Same number of rows either way; this only decides where the break
	// falls.
	rows := (len(cells) + perRow - 1) / perRow
	perRow = (len(cells) + rows - 1) / rows

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
	laneListHint = "↑/↓ move   enter details   f fix   space select   m select lane   a fix marked\n" +
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

// messageRows draws the one-screen result of an action — a fix applied, a
// rollback done, a batch finished, or the error from any of them.
//
// It wraps each line of m.status separately and keeps the blank ones, which
// is the whole difference from what it did before. The summaries hand it a
// what-happened line, the facts under it, and a warning below those; wrapping
// the lot as one paragraph — which is what textwidth.Wrap does, since
// strings.Fields treats a newline as a space — turned four separate facts
// into a run-on remark that broke wherever the column happened to fall.
func (m *appModel) messageRows(n int) []string {
	s := m.sty()
	var out []string
	for _, para := range strings.Split(m.status, "\n") {
		if strings.TrimSpace(para) == "" {
			out = append(out, "")
			continue
		}
		out = append(out, m.wrapRows(s.bone, para, m.proseWidth(bodyInset), bodyInset)...)
	}
	return centerRows(out, n)
}

// scanningRows draws the scan in progress: a bar over the domains that will
// run, one row each, and how long it has been going.
//
// It used to be the status line alone, centred in an otherwise empty frame,
// which answered neither question an operator has while waiting. "Is it
// hung?" needs to name what is working now — almost always the CVE domain,
// which on a host with many images takes minutes. "How far in?" needs a
// denominator, which the events cannot supply and the engine can.
//
// There is deliberately no estimate of the time remaining. Eleven of the
// twelve domains together finish inside a second; the twelfth shells out to
// Trivy, whose duration depends on the images, their size, and whether the
// vulnerability database needs downloading first. Nearly all of the unknown
// is in the one domain nothing can predict, and a number that is confidently
// wrong for the whole wait is worse than no number — the same reason a
// skipped domain is scored N/A rather than 100.
func (m *appModel) scanningRows(n int) []string {
	s := m.sty()
	domains := m.scanDomains()
	if len(domains) == 0 {
		// Nothing has been heard yet and there was no engine to ask. The
		// status line is all there is, and it is what this screen was.
		return centerRows(m.wrapRows(s.dim, m.status, m.proseWidth(bodyInset), bodyInset), n)
	}

	// Narrow enough to read as one block rather than a band across a wide
	// terminal, and wide enough for the longest domain name beside its state.
	width := min(m.proseWidth(bodyInset), 34)
	head := fmt.Sprintf("Scanning %d of %d domains", m.scanDone, len(domains))
	if m.scanElapsed >= time.Second {
		head += "   " + formatElapsed(m.scanElapsed)
	}

	rows := []string{
		s.brand.Render(head),
		s.meterAtLeastOne(scanPercent(m.scanDone, len(domains)), width, s.cAccent, m.scanDone > 0),
		"",
	}
	for _, src := range domains {
		rows = append(rows, m.scanDomainRow(src, width))
	}
	return centerRows(indentRows(rows, bodyInset), n)
}

// scanPercent is how much of the plan has finished, as a meter takes it.
func scanPercent(done, total int) uint8 {
	if total <= 0 {
		return 0
	}
	//nolint:gosec // G115: done <= total, so the quotient is bounded by 100
	return uint8(min(100, done*100/total))
}

// scanDomainRow is one domain's line: a mark, its name, and where it got to,
// with the state right-aligned so the column reads down and the row is exactly
// as wide as the bar above it.
//
// The mark comes from the glyph table because these are the same states the
// coverage notices draw at the end of a scan, and a domain reported as skipped
// while running must not be marked differently from the same domain in the
// report a second later.
//
// Every piece is measured and cut before it is styled. Truncating the styled
// row instead cuts inside an escape sequence — truncate counts columns of the
// bytes it is given, and an escape is bytes with no columns — which puts the
// sequence's own digits on the screen.
func (m *appModel) scanDomainRow(src model.Source, width int) string {
	s := m.sty()

	mark, style, note := " ", s.dim, "waiting"
	switch m.scanState[src] {
	case model.ScanRunning:
		mark, style, note = m.gl.Of(glyph.Cursor), s.bone, "scanning…"
	case model.ScanDone:
		mark, style, note = m.gl.Of(glyph.OK), s.safe, "done"
	case model.ScanSkipped:
		mark, style, note = m.gl.Of(glyph.Skipped), s.dim, "skipped"
	case model.ScanDegraded:
		mark, style, note = m.gl.Of(glyph.Partial), lipgloss.NewStyle().Foreground(s.cHigh), "partial"
	case model.ScanError:
		mark, style, note = m.gl.Of(glyph.Failed), lipgloss.NewStyle().Foreground(s.cCrit), "failed"
	case model.ScanPending:
	}

	markW := lipgloss.Width(mark) + 1
	noteW := lipgloss.Width(note)
	nameW := max(1, width-markW-noteW-1)
	name := truncate(src.Label(), nameW)
	gap := max(1, width-markW-lipgloss.Width(name)-noteW)
	return style.Render(mark+" "+name) + strings.Repeat(" ", gap) + s.dim.Render(note)
}

// formatElapsed writes a duration the way a stopwatch does. Seconds only up
// to a minute, because that is the whole of an ordinary scan.
func formatElapsed(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	return fmt.Sprintf("%d:%02d", secs/60, secs%60)
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

	// The band spans the columns it leads, which is every column except the
	// rail. In the dashboard the rail is a sibling of everything else and
	// runs the full height of the window, so the verdict sits *beside* it
	// rather than above it; the arrangement that draws both would otherwise
	// read as a different arrangement in the two interfaces, which is the one
	// thing the shared registry exists to prevent.
	spanW := m.width
	if railW > 0 {
		spanW = listW
	}
	var lead []string
	if m.wantsVerdict() {
		if v := m.verdictRows(spanW); len(v)+minVerdictBody <= budget {
			lead = v
		}
	}
	inner := budget - len(lead)

	list := m.listColumn(inner, listW)
	if railW == 0 && paneW == 0 {
		return append(lead, fitRows(list, inner)...)
	}

	// Where the rail is drawn the band belongs to the list's own column, so
	// the rail keeps the whole height beside it.
	rows := inner
	if railW > 0 {
		list = append(lead, list...)
		lead, rows = nil, budget
	}

	widths := make([]int, 0, 3)
	cols := make([][]string, 0, 3)
	if railW > 0 {
		widths = append(widths, railW)
		cols = append(cols, m.railRows(railW, rows))
	}
	widths = append(widths, listW)
	cols = append(cols, list)
	if paneW > 0 {
		widths = append(widths, paneW)
		cols = append(cols, m.paneRows(paneW, rows))
	}
	return append(lead, m.joinColumns(rows, widths, cols)...)
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
	f := m.active[m.cursor]
	body := indentRows(m.detailBodyRows(f, max(textwidth.MinWrap, min(w-2*paneInset, maxProse))), paneInset)
	out := make([]string, 0, len(body)+4)
	out = append(out, body...)
	// The dashboard closes this pane with a row of buttons — Preview fix,
	// Explain with AI — and the terminal closed it with nothing, leaving the
	// two keys that act on what the pane is showing documented only in the
	// footer, among fourteen others. A pane that reads a finding out and then
	// does not say what can be done about it is where the two interfaces
	// diverged most, and it is the cheapest place to stop.
	//
	// The divider is drawn at the pane's own width and *not* indented with the
	// rows around it: it is the one row here that has to meet the separator to
	// its left, and joinColumns can only turn that meeting into a ├ if the
	// rule actually reaches the column edge.
	out = append(out, "", m.ruleRowOf(w))
	out = append(out, indentRows(m.paneActionRows(f), paneInset)...)
	return m.clipRows(out, budget)
}

// paneActionRows is what the dashboard draws as buttons under the detail: the
// keys that act on this finding, and only the ones that would do something.
func (m *appModel) paneActionRows(f model.Finding) []string {
	s := m.sty()
	var acts []string
	if f.IsFixable() {
		acts = append(acts, s.safe.Render("f  preview and apply the fix"))
	}
	acts = append(acts, s.dim.Render("e  explain with AI")+
		s.dim.Render("     enter  open full screen"))
	return acts
}

// emptyListRows is what the list column says when there is nothing in it: a
// clean host, a filter that matched nothing, or a host nobody could look at.
//
// "Clean" is a claim about the whole host, so it may only be made when the
// whole host was examined. The CLI has always drawn that line; this view and
// the dashboard both said "Clean." unconditionally, so a host whose every
// checker failed read as spotless in two interfaces out of three.
//
// The message has to stand on its own here. The CLI can say "see above"
// because it prints a per-domain status block first; this view prints none,
// so it names the count itself.
func (m *appModel) emptyListRows(chips string, w int) []string {
	s := m.sty()
	switch {
	case m.filterActive():
		// Asked explicitly rather than inferred from the chip row: the chips
		// are drawn from the unfiltered report, so they are there whenever the
		// host has findings at all, filtered or not.
		return []string{chips, "", indentRows([]string{s.dim.Render("No findings match the filter.")}, bodyInset)[0]}
	case m.report.IncompleteDomains() > 0:
		// Wrapped, for the reason the preview's warning is wrapped: this row is
		// far longer than the "Clean." it replaces, and clipped at the terminal
		// edge it degrades into "No problems found in the domains that" — which
		// reads as the very claim it exists to withhold.
		warn := lipgloss.NewStyle().Foreground(s.cHigh)
		msg := fmt.Sprintf("No problems found in the domains that ran — but %d did not complete.",
			m.report.IncompleteDomains())
		return m.wrapRows(warn, msg, max(textwidth.MinWrap, min(w-2*bodyInset, maxProse)), bodyInset)
	default:
		return indentRows([]string{s.safe.Render("No problems found. Clean.")}, bodyInset)
	}
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

	fl := m.chipRow(w)
	if len(m.active) == 0 {
		return centerRows(m.emptyListRows(fl, w), budget)
	}

	// The chip row and the batch bar are the dashboard's two rows over the
	// list, in the same order it draws them.
	bb := m.batchRow(w)
	chrome := 1
	if fl != "" {
		chrome++
	}
	if bb != "" {
		chrome++
	}
	visible := budget - chrome
	if visible < 1 {
		// Findings beat labels: on a frame this short the list itself is the
		// only thing worth drawing.
		chrome, visible = 0, budget
	} else if chrome > 1 && visible < minChipRows {
		// The chips and the batch bar summarise the list, and a summary that
		// costs half of what it summarises is not worth its rows. Both go at
		// once: dropping one and keeping the other would leave the shorter
		// frame carrying the less useful of the two.
		chrome, visible = 1, budget-1
		fl, bb = "", ""
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
		h := s.accent.Render(count)
		if n := len(m.selected); n > 0 {
			h += s.safe.Render(fmt.Sprintf("   %s %d marked", m.gl.Of(glyph.OK), n))
		}
		if total > visible {
			h += s.dim.Render(fmt.Sprintf("      %d–%d", shownFrom, shownTo))
		}
		// listPad: the chip's own background already starts one column left
		// of its label, so the head and the batch bar are moved in by one to
		// put all three labels on the same column. The dashboard does this
		// with one padding on the three containers; here the chip is the only
		// one carrying its padding inside itself.
		const listPad = 1
		out = append(out, indentRows([]string{h}, listPad)...)
		if fl != "" {
			out = append(out, fl)
		}
		if bb != "" {
			out = append(out, indentRows([]string{bb}, listPad)...)
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
// A severity with nothing at it gets no lane: a "HIGH · 0" heading is a
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
			if f.IsAutoFixable() {
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
		if f.Active() {
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
	// The marker column is one width for every row, measured rather than
	// assumed to be two. "·" and the tick are East Asian Ambiguous, so on a
	// terminal that draws that class wide they are two columns each and a
	// marked row started its severity one column right of an unmarked one —
	// the whole list stepping in and out down the left edge.
	markW := m.markColumns()
	mark := padRight("", markW)
	if f.IsAutoFixable() {
		if m.selected[f.Key()] {
			mark = s.safe.Render(padRight(m.gl.Of(glyph.OK)+" ", markW))
		} else {
			// Safe, not slate. The dot means hostveil can fix this row by
			// itself, which is the same claim the FIXABLE chip makes and
			// spends the same color on — and drawn in the muted grey it was
			// the only mark on the screen that said something while looking
			// like it did not.
			mark = s.safe.Render(padRight("· ", markW))
		}
	}
	sev := sevAbbr(f.Severity)
	kind := kindCell(f)

	// Budget the row from what is actually drawn rather than a fixed 46.
	// The old constant did not account for the trailing service suffix at
	// all, so a finding on "cloud/nextcloud-12" overran the terminal by
	// however long the service name happened to be — and it did not account
	// for an ID longer than its field either. Both are host-supplied, so
	// neither has a safe upper bound.
	gutterAndMark := lipgloss.Width("▌") + markW
	idW := m.idColumnWidth(w)
	body := fmt.Sprintf("%-4s %-*s %-*s ", sev, kindColumns, kind, idW, truncate(f.ID, idW))

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
	//
	// This is computed once, for the cursor row and every other row alike.
	// It used to be computed twice, and the cursor branch simply did not do
	// the suffix half — so moving the cursor onto a row erased the one
	// column that said which container it was about, on the row the operator
	// was by definition looking at.
	const minTitleWidth = 16
	plainSuffix := serviceLabel(f)
	avail := w - gutterAndMark - lipgloss.Width(body)
	if sw := lipgloss.Width(plainSuffix); sw > avail || avail-sw < minTitleWidth {
		plainSuffix = ""
	}
	title := truncate(f.Title, avail-lipgloss.Width(plainSuffix))

	// The service is set flush right, the way the dashboard's row does it,
	// rather than trailing the title. Two reasons, and the second is the one
	// that matters on a wide terminal: it makes a column of service names the
	// eye can run down, and it stops the service from sliding left to right
	// with every title length so that "which container is this?" is answered
	// in one place instead of eighty.
	//
	// Always, whatever the gap. This used to right-align only where at least
	// four columns separated the two, on the reasoning that a name one space
	// from the title is not a column — which is true of that row read on its
	// own and false of the list it sits in. A row whose title happened to land
	// three columns short ended three columns short, so the column of service
	// names ran down the list and then stepped sideways for one row and back,
	// once per finding whose title was nearly long enough. Ragged in a way
	// that reads as a rendering fault, and next to a pane separator it *is*
	// one: the row no longer reaches the line beside it.
	if gap := avail - lipgloss.Width(title) - lipgloss.Width(plainSuffix); plainSuffix != "" && gap > 0 {
		title = padRight(title, lipgloss.Width(title)+gap)
	}

	if cursor {
		// One Render over the whole row. The suffix cannot carry its own dim
		// style here — inverse video is the selection, and a second colour
		// inside it reads as a rendering fault rather than as a quieter
		// column.
		return gutter + mark + s.sel.Render(padRight(body+title+plainSuffix, w-gutterAndMark))
	}

	// The severity is padded to the same %-4s the budget above was computed
	// from. It was not, and the two disagreed by exactly the difference
	// between "HIGH" and "MED": every medium and low row was rendered a column
	// narrower than the arithmetic that laid it out, so the id column stepped
	// left for those rows and the right-aligned service stopped one short of
	// the pane separator. Two visible faults, one missing pad.
	return gutter + mark +
		lipgloss.NewStyle().Foreground(sevC).Render(fmt.Sprintf("%-4s", sev)) +
		s.kindStyle(f).Render(fmt.Sprintf(" %-*s", kindColumns, kind)) +
		s.dim.Render(fmt.Sprintf(" %-*s ", idW, truncate(f.ID, idW))) +
		s.bone.Render(title) + s.dim.Render(plainSuffix)
}

// kindColumns is the width of the remediation column. Six, because that is
// the longest abbreviation the enum has ("review", "manual"), and the column
// is padded to it so the id column below it does not step left and right
// down the list.
const kindColumns = 6

// kindCell is what the remediation column says for a row.
//
// A pending row does not report its RemediationKind. The kind answers "what
// is there to do about this", and for a row hostveil has already fixed the
// answer is no longer "auto" — nothing is going to be pressed here, and the
// row is still on the list only because the change has not reached the host.
// Showing AUTO there would invite the operator to apply a fix that has
// already been applied, on the one row where doing so achieves nothing.
//
// Abbreviated to fit the column rather than widening it, which is what this
// column has always done — HIGH, MED, AUTO and N/A are all short for
// something. "PENDING" would have cost every row on every screen a column of
// title, permanently, to carry a state most rows never enter. The full word
// is in the JSON, on the dashboard chip and in the sentence under the row,
// all three of which have the room.
func kindCell(f model.Finding) string {
	if f.Pending {
		return "PEND"
	}
	return kindAbbr(f.Remediation)
}

func kindAbbr(r model.RemediationKind) string {
	return strings.ToUpper(r.Abbr())
}

// markColumns is the width of the pick-marker column, which is the widest of
// the three things that can be drawn in it. Two columns on every terminal
// that draws ambiguous characters narrow, and the point of measuring is the
// one that does not.
func (m *appModel) markColumns() int {
	return max(2, lipgloss.Width(m.gl.Of(glyph.OK)+" "), lipgloss.Width("· "))
}

// idColumnWidth is how wide the finding-id column is drawn, for every row in
// the list at once.
//
// It used to be a literal 13, which is neither the widest id nor a bound on
// one: cve.outdated-image is eighteen columns and simply pushed its own title
// five to the right of every other title on the screen. A column that only
// holds for the ids that happen to be short is not a column, and the ragged
// left edge it produced is the first thing the eye catches in a list that is
// otherwise a grid.
//
// So: the widest id actually on screen, floored at the common case so a list
// of short ids does not close the gap the titles are read across, and capped
// at a third of the column so one long id cannot spend the title's room.
func (m *appModel) idColumnWidth(w int) int {
	const floor = 13
	widest := floor
	for _, f := range m.active {
		widest = max(widest, lipgloss.Width(f.ID))
	}
	return min(widest, max(floor, w/3))
}

// batchRow is the terminal's batch bar: the dashboard has a row of buttons
// over the list saying what a batch would do, and the terminal had the same
// information only in the footer, where it reads as one more key among
// fourteen rather than as the state the list is in.
//
// It says what pressing the key does *now*, which is the whole point — `a`
// applies the marked findings, or every Auto finding when nothing is marked,
// and those are different enough that a bar naming only one of them would be
// wrong half the time.
func (m *appModel) batchRow(w int) string {
	s := m.sty()
	// The current filter, not the whole report: `a` applies over the list
	// that is on screen, and a bar counting anything else promises work the
	// key will not do. See Report.AutoFixable.
	autos := len(m.report.AutoFixable(m.filter))
	switch {
	case len(m.selected) > 0:
		return clip(s.safe.Render(fmt.Sprintf("a  fix the %d marked", len(m.selected)))+
			s.dim.Render("     esc  clear marks"), w)
	case autos > 0:
		return clip(s.safe.Render(fmt.Sprintf("a  fix all %d safe", autos))+
			s.dim.Render("     space  mark one"), w)
	}
	return ""
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
// High, how much of it hostveil can fix on its own — was reachable only
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
// above it reads as active — anything else would dim the HIGH chip on a
// list that is showing exactly the High findings.
func (m *appModel) chipRow(w int) string {
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

	var chips []chipSpec
	for _, sev := range model.AllSeverities() {
		n := counts[sev]
		if n == 0 {
			continue // the dashboard omits a severity nothing is at, too
		}
		on := m.filter.MinSeverity != nil && sev <= *m.filter.MinSeverity
		chips = append(chips, chipSpec{fmt.Sprintf("%s %d", sevAbbr(sev), n), on, s.severityColor(sev)})
	}
	if fixable > 0 {
		// Safe rather than the dashboard's slate. "Fixable" is a claim about
		// safety, which is the one thing besides risk this design system lets
		// a color mean, and spending it here is what makes the count read as
		// the good news it is.
		chips = append(chips, chipSpec{fmt.Sprintf("FIXABLE %d", fixable), m.filter.FixableOnly, s.cSafe})
	}
	if m.filter.Source != model.SourceUnset {
		chips = append(chips, chipSpec{strings.ToUpper(sourceLabel(m.filter.Source)), true, s.cSlate})
	}
	return m.fitChips(chips, w)
}

// chipSpec is one chip before it is drawn. The row has to decide which chips
// survive a narrow column, and that decision is about the chip rather than
// about the escape sequences it renders to.
type chipSpec struct {
	label string
	on    bool
	color color.Color
}

// fitChips joins the chips that fit and says how many did not.
//
// Clipping the joined row instead is what the frame used to do, and it cut
// through a chip rather than between two: the console arrangement narrows the
// list column enough that "FIXABLE 38" came out as "FIXABLE 3". A truncated
// label is obviously truncated; a truncated *count* is a different number,
// and this row exists to be read as numbers.
//
// A chip that is on is never dropped. The fill is what says which filter is
// running, and for the domain filter this row is the only place the domain is
// named at all — the head line's "FINDINGS · 3/26" says the list is narrowed
// but not by what. So the active ones are kept and the rest fill the room
// that is left, in their own order.
func (m *appModel) fitChips(chips []chipSpec, w int) string {
	if len(chips) == 0 {
		return ""
	}
	draw := func(keep []chipSpec, dropped int) string {
		parts := make([]string, 0, len(keep))
		for _, c := range keep {
			parts = append(parts, m.chip(c.label, c.on, c.color))
		}
		row := strings.Join(parts, "  ")
		if dropped > 0 {
			row += m.overflowTail(dropped)
		}
		return row
	}
	if full := draw(chips, 0); w <= 0 || lipgloss.Width(full) <= w {
		return full
	}

	// Room for the marker is held back before anything is admitted, so it is
	// never itself the thing that gets clipped.
	budget := w - overflowTailWidth
	room := budget
	keep := make([]bool, len(chips))
	for i, c := range chips {
		if !c.on {
			continue
		}
		keep[i] = true
		room -= lipgloss.Width(m.chip(c.label, c.on, c.color)) + 2
	}
	for i, c := range chips {
		if keep[i] {
			continue
		}
		cw := lipgloss.Width(m.chip(c.label, c.on, c.color)) + 2
		if room-cw < 0 {
			break // in order, so what is dropped is always a suffix of the rest
		}
		keep[i] = true
		room -= cw
	}

	out, dropped := make([]chipSpec, 0, len(chips)), 0
	for i, c := range chips {
		if keep[i] {
			out = append(out, c)
			continue
		}
		dropped++
	}
	if len(out) == 0 {
		// Every chip is wider than the column. One chip and the marker still
		// beats an empty row that claims there is nothing to filter by.
		return clip(draw(chips[:1], len(chips)-1), w)
	}
	return clip(draw(out, dropped), w)
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
			errored = append(errored, fail.Render(m.notice(m.gl.Of(glyph.Failed), name, "failed", d.Reason, "unknown error")))
		case model.ScanDegraded:
			degraded = append(degraded, warn.Render(m.notice(m.gl.Of(glyph.Partial), name, "partial", d.Reason, "covered only part of the domain")))
		case model.ScanSkipped:
			skipped = append(skipped, s.dim.Render(m.notice(m.gl.Of(glyph.Skipped), name, "skipped", d.Reason, "did not run")))
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
		rows = append(rows, s.dim.Render(fmt.Sprintf("%s %d more domain(s) did not fully run — hostveil scan lists them", m.gl.Of(glyph.Skipped), hidden)))
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

// serviceLabel is the unstyled suffix. It is unstyled because the cursor row
// needs the same text inside one inverse-video Render, and a pre-styled
// string cannot be put there — which is how the cursor row came to be built
// by a separate branch that dropped the suffix entirely.
func serviceLabel(f model.Finding) string {
	if f.Service == "" {
		return ""
	}
	return "  (" + f.Service + ")"
}

func (m *appModel) serviceSuffix(f model.Finding) string {
	return m.sty().dim.Render(serviceLabel(f))
}

func (m *appModel) detailRows() []string {
	if len(m.active) == 0 {
		return nil
	}
	return append([]string{""},
		indentRows(m.detailBodyRows(m.active[m.cursor], m.proseWidth(bodyInset)), bodyInset)...)
}

// detailBodyRows is one finding written out, wrapped to w.
//
// It takes the finding and the width rather than reading the cursor and
// m.width because three things now render it: the full-screen detail view,
// the detail pane beside the list, and the block that opens inline under a
// row. They differ in how much room they have and in nothing else, and a
// second copy of this text is a second place for the AI box to be forgotten.
func (m *appModel) detailBodyRows(f model.Finding, w int) []string {
	return append(m.detailHeaderRows(f, w), m.detailFactsRows(f, w)...)
}

// detailHeaderRows names the finding: severity and title, then the id, the
// remediation kind and the service under them.
//
// It is split from the facts because the inline block does not want it. That
// block is drawn immediately under the list row for the same finding, and the
// row above it already carries the severity and the id — so two of these three
// lines said again, four columns to the right, what the reader had just read.
// The facts below are the same text in all three places and stay in one copy,
// which is what the note on detailBodyRows is protecting.
func (m *appModel) detailHeaderRows(f model.Finding, w int) []string {
	s := m.sty()
	head := lipgloss.NewStyle().Foreground(s.severityColor(f.Severity)).Bold(true).Render(strings.ToUpper(f.Severity.String())) +
		"  " + s.brand.Render(truncate(f.Title, max(1, w-lipgloss.Width(f.Severity.String())-2)))
	return []string{head, s.dim.Render(truncate(m.detailMeta(f, true), w)), ""}
}

// detailMeta is the id/kind/service line. withID is false where the row above
// is already showing the id.
func (m *appModel) detailMeta(f model.Finding, withID bool) string {
	meta := strings.ToUpper(f.Remediation.String())
	if withID {
		meta = strings.ToUpper(f.ID + "  ·  " + f.Remediation.String())
	}
	if f.Service != "" {
		meta += "  ·  SERVICE: " + f.Service
	}
	return meta
}

// detailFactsRows is everything a finding says about itself: what it means,
// how to fix it, why there is no button where there is none, and the AI note.
func (m *appModel) detailFactsRows(f model.Finding, w int) []string {
	s := m.sty()
	out := styledRows(s.bone, wrap(f.Description, w))
	if f.HowToFix != "" {
		out = append(out, "", s.accent.Render("HOW TO FIX"))
		out = append(out, styledRows(s.bone, wrap(f.HowToFix, w))...)
	}
	// Under the instructions, not above them: a reader with no fix button
	// still needs the how-to first, and this answers the question they ask
	// second. Dim, because it explains an absence rather than asking for
	// anything.
	if f.WhyNoFix != "" {
		out = append(out, "", s.accent.Render("WHY THERE IS NO FIX BUTTON"))
		out = append(out, styledRows(s.dim, wrap(f.WhyNoFix, w))...)
	}
	if m.aiBusy || m.aiText != "" || m.aiErr != "" {
		out = append(out, "", s.accent.Render("AI EXPLANATION (ADVISORY)"))
		switch {
		case m.aiBusy:
			out = append(out, s.dim.Render("asking the local AI model…"))
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

	// What this fix is, before what it does. The header above carries only the
	// fix's label, so the screen an operator reads immediately before pressing
	// y did not name the finding it repairs, whether hostveil considers it
	// safe to apply unattended, or the file it edits — while the rollback
	// confirmation, which asks a strictly smaller question, said all three.
	meta := strings.ToUpper(m.preview.FindingID + "  ·  " + m.preview.Kind.String())
	if p := m.preview.Actions[clamp(m.previewAction, 0, len(m.preview.Actions)-1)].Path; p != "" {
		meta += "  ·  " + p
	}
	out := []string{""}
	out = append(out, indentRows([]string{s.dim.Render(truncate(meta, m.proseWidth(bodyInset)))}, bodyInset)...)
	out = append(out, "")

	// Every block below sits at bodyInset and every nested one a step further
	// in, which is what the dashboard's .fixbox-body does with padding: the
	// label, the options under it, the warning, the commands.
	if len(m.preview.Actions) > 1 {
		out = append(out, indentRows([]string{s.dim.Render("Alternatives (press a number):")}, bodyInset)...)
		for _, a := range m.preview.Actions {
			marker := strings.Repeat(" ", stepInset)
			if a.Index == idx {
				marker = lipgloss.NewStyle().Foreground(s.cBone).Render(m.gl.Of(glyph.Cursor) + " ")
			}
			row := marker + s.bone.Render(truncate(fmt.Sprintf("[%d] %s", a.Index, a.Label),
				m.proseWidth(bodyInset)-stepInset))
			out = append(out, indentRows([]string{row}, bodyInset)...)
		}
		out = append(out, "")
	}

	a := m.preview.Actions[idx]
	if a.Warning != "" {
		// It is the one place the preview explains what cannot be undone, and
		// unwrapped it ran past the terminal edge and was clipped mid-sentence
		// — cut, in the exec case, at "There is no rollback" with the reason
		// that follows lost. Hanging, so the continuation sits under the text
		// rather than under the marker.
		out = append(out, m.hangingRows(lipgloss.NewStyle().Foreground(s.cHigh),
			m.gl.Of(glyph.Warning)+"  ", a.Warning, m.proseWidth(bodyInset), bodyInset)...)
		out = append(out, "")
	}

	switch a.Type {
	case "edit", "mode":
		out = append(out, indentRows(s.diffRows(a.Diff), bodyInset)...)
		// The reassurance belongs on the screen where the decision is made.
		// An exec action already says the opposite here, through its warning
		// — "there is no rollback checkpoint" — and saying only the alarming
		// half leaves the operator to infer the safe half from its absence.
		out = append(out, "")
		out = append(out, indentRows([]string{s.safe.Render(
			m.gl.Of(glyph.OK) + " hostveil backs the file up before writing, and h undoes this.")}, bodyInset)...)
	case "exec":
		out = append(out, indentRows([]string{s.dim.Render("These commands will run:")}, bodyInset)...)
		for _, cmd := range a.Commands {
			out = append(out, indentRows([]string{s.dim.Render(truncate("$ "+strings.Join(cmd, " "),
				max(textwidth.MinWrap, m.width-bodyInset-stepInset)))}, bodyInset+stepInset)...)
		}
	default:
		// Never leave the apply/cancel footer with an empty body above it.
		out = append(out, indentRows([]string{
			s.dim.Render("(no preview available for action type " + a.Type + ")")}, bodyInset)...)
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
			Render(m.gl.Of(glyph.Warning) + " " + truncate(m.historyWarning, max(1, m.width-2)))
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
	idW := m.checkpointIDWidth()
	for i := m.cpOffset; i < end; i++ {
		out = append(out, m.checkpointRow(m.checkpoints[i], i == m.cpCursor, idW))
	}
	// One margin for the whole screen, the header and the warning included:
	// this is a list of prose rows with no severity gutter to sit at the edge,
	// which is the difference between it and the findings list.
	return indentRows(out, bodyInset)
}

// checkpointRow is one applied fix: when, what it was about, what it did.
//
// The id column is measured, not assumed. At a fixed %-15s every id longer
// than fifteen — firewall.inactive, fileperms.sshd-config, updates.disabled, all
// of them ordinary — pushed its own label right, so the labels stepped in and
// out down a list whose whole job is to be scanned for the one you want to
// undo.
func (m *appModel) checkpointRow(cp model.Checkpoint, cursor bool, idW int) string {
	s := m.sty()
	const whenW = 11 // "01-02 15:04"
	when := cp.CreatedAt.Local().Format("01-02 15:04")
	id := truncate(cp.FindingID, idW)
	inner := max(textwidth.MinWrap, m.width-2*bodyInset)
	label := truncate(cp.Label, max(1, inner-whenW-idW-2))
	line := fmt.Sprintf("%-*s %-*s %s", whenW, when, idW, id, label)
	if cursor {
		return s.sel.Render(padRight(line, inner))
	}
	if !cp.Reversible {
		return s.dim.Render(line)
	}
	return s.dim.Render(when+" ") + s.bone.Render(fmt.Sprintf("%-*s ", idW, id)) +
		s.bone.Render(label)
}

// checkpointIDWidth sizes that column from the entries on screen, bounded so
// one long id cannot leave no room for the labels beside it.
func (m *appModel) checkpointIDWidth() int {
	const floor, ceiling = 15, 24
	widest := floor
	for _, cp := range m.checkpoints {
		widest = max(widest, lipgloss.Width(cp.FindingID))
	}
	return min(widest, max(floor, min(ceiling, (m.width-2*bodyInset)/3)))
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
			marker = lipgloss.NewStyle().Foreground(s.cBone).Render(m.gl.Of(glyph.Cursor) + " ")
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
	out = append(out, m.wrapRows(s.dim, "Colors mean the same thing in every theme: the severity steps, "+
		"the score bands, and safety. Everything else is chrome.", m.proseWidth(bodyInset), bodyInset)...)
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
			marker = lipgloss.NewStyle().Foreground(s.cBone).Render(m.gl.Of(glyph.Cursor) + " ")
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

	out := []string{""}
	out = append(out, indentRows([]string{s.dim.Render("Restores:")}, bodyInset)...)
	for _, p := range cp.Files {
		out = append(out, indentRows([]string{s.bone.Render(truncate(p,
			max(textwidth.MinWrap, m.width-bodyInset-stepInset)))}, bodyInset+stepInset)...)
	}
	out = append(out, "")
	if cp.RestartService != "" {
		out = append(out, m.hangingRows(lipgloss.NewStyle().Foreground(s.cHigh),
			m.gl.Of(glyph.Warning)+"  ", "You may need to restart '"+cp.RestartService+"' afterwards.",
			m.proseWidth(bodyInset), bodyInset)...)
		out = append(out, "")
	}
	if cp.Diff != "" {
		out = append(out, indentRows([]string{s.dim.Render("This change will be reverted:")}, bodyInset)...)
		out = append(out, indentRows(s.diffRows(cp.Diff), bodyInset)...)
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
	out = append(out, m.wrapRows(lipgloss.NewStyle().Foreground(s.cHigh), m.status,
		m.proseWidth(bodyInset), bodyInset)...)
	out = append(out, "")
	out = append(out, m.wrapRows(s.bone,
		"Forcing the rollback restores hostveil's backup over the current file, discarding those changes. "+
			"Rollback writes no checkpoint of its own, so this cannot be undone.",
		m.proseWidth(bodyInset), bodyInset)...)
	if len(m.checkpoints) > 0 {
		cp := m.checkpoints[m.cpCursor]
		out = append(out, "")
		out = append(out, indentRows([]string{s.dim.Render("Would overwrite:")}, bodyInset)...)
		for _, p := range cp.Files {
			out = append(out, indentRows([]string{s.bone.Render(truncate(p,
				max(textwidth.MinWrap, m.width-bodyInset-stepInset)))}, bodyInset+stepInset)...)
		}
	}
	return out
}

// overflowTail is how a strip that gets exactly one row says what it could
// not fit. Two of them need it — the axes spark and the chip row — and a
// second spelling of the same idea is how "+3" and "3 more" end up on
// adjacent rows meaning the same thing.
//
// overflowTailWidth is what a caller holds back for it before admitting
// anything, so the marker is never the part that gets clipped. Four columns
// covers "  +9"; past nine dropped items the row is far too narrow to be
// reading counts off anyway.
const overflowTailWidth = 4

func (m *appModel) overflowTail(n int) string {
	return m.sty().dim.Render(fmt.Sprintf("  +%d", n))
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

// --- indentation ---------------------------------------------------------
//
// The dashboard pads a region and lets everything inside it align to that
// padding — `.detail { padding: 16px 22px }`, the filter bar and the batch
// bar `9px 14px` — so a paragraph that wraps keeps its left edge, because
// the padding belongs to the box and not to the first line of what is in it.
// A terminal has to do that by hand, and where this did not, it showed:
//
//   - the applied-fix message indented its first line two columns and
//     continued at zero, because "  " was prepended to the string and the
//     wrap happened after
//   - the preview's alternatives sat at two columns under a label at zero,
//     its commands at two under a label at zero, and its warning at zero
//   - the theme picker's paragraph ran to the frame edge under a list that
//     did not, and the rollback screen mixed all three
//
// One vocabulary, used by every screen:
//
//	bodyInset  the left margin of a full-screen body
//	paneInset  the same inside a column, where the separator is the edge and
//	           a second column of margin is one the list wanted
//	stepInset  a nested list under a label — options, paths, commands
const (
	bodyInset = 2
	paneInset = 1
	stepInset = 2
)

// maxProse caps a line of running text at the measure the dashboard caps it
// at (`.detail p { max-width: 74ch }`), so a 200-column terminal sets the
// same paragraph the browser does rather than one 200 columns wide.
const maxProse = 74

// proseWidth is how wide running text is set inside a region with this
// margin on both sides.
func (m *appModel) proseWidth(inset int) int {
	return max(textwidth.MinWrap, min(m.width-2*inset, maxProse))
}

// indentRows shifts every row right, wrapped continuations included. Blank
// rows stay blank rather than becoming rows of spaces.
func indentRows(rows []string, n int) []string {
	if n <= 0 {
		return rows
	}
	pad := strings.Repeat(" ", n)
	out := make([]string, len(rows))
	for i, r := range rows {
		if r == "" {
			out[i] = ""
			continue
		}
		out[i] = pad + r
	}
	return out
}

// wrapRows sets text to contentW columns and indents every line of it by n.
func (m *appModel) wrapRows(st lipgloss.Style, text string, contentW, n int) []string {
	if text == "" {
		return nil
	}
	return indentRows(styledRows(st, wrap(text, max(textwidth.MinWrap, contentW))), n)
}

// hangingRows is wrapRows for a block led by a marker — the ⚠ of a warning —
// where the continuation lines align under the text rather than under the
// marker.
func (m *appModel) hangingRows(st lipgloss.Style, marker, text string, contentW, n int) []string {
	lead := lipgloss.Width(marker)
	lines := strings.Split(wrap(text, max(textwidth.MinWrap, contentW-lead)), "\n")
	out := make([]string, 0, len(lines))
	for i, l := range lines {
		if i == 0 {
			out = append(out, st.Render(marker+l))
			continue
		}
		out = append(out, st.Render(strings.Repeat(" ", lead)+l))
	}
	return indentRows(out, n)
}

// wrap reflows s to width display columns.
//
// It used to count bytes, so Hangul wrapped at roughly two-thirds of the
// width it was given — 24 columns used of 40. `explain --ai` renders
// whatever the local model wrote, which is the path that reaches this with
// text the byte count is wrong about.
func wrap(s string, width int) string { return textwidth.Wrap(s, width, "") }

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
