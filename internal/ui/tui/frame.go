package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/glyph"
	"github.com/seolcu/hostveil/internal/model"
)

// This file owns the shape of the screen: how a frame is assembled, how tall
// each region is, and what happens when the terminal is too small for all of
// it. No mode composes its own frame.
//
// It replaces a scheme where every view appended to a strings.Builder and the
// two scrolling views worked out their row budget by counting the newlines of
// chrome they had *already rendered* (`reserved := strings.Count(hdr, "\n") +
// strings.Count(ftr, "\n") + 3`). That arithmetic was the direct cause of two
// separate fixed bugs, because it had to be re-derived by hand every time the
// chrome changed, and getting it wrong pushed the key hints off the bottom of
// the alt screen with nothing to say they had gone. Here the chrome is
// measured first and the body is *told* what it may use.

// minBodyRows is how much room the findings list must keep for the full axes
// strip to be worth drawing. Below it the header drops to the one-line tier:
// a score breakdown is context, and context that leaves no room for the thing
// it is context *for* is worse than no context.
const minBodyRows = 6

// minChipRows is how many findings must remain visible for the chip row to
// be worth its own row. Below it the summary would be competing with the
// thing it summarises for the same three lines.
const minChipRows = 4

// Fallback terminal size, used until the first WindowSizeMsg arrives and by
// every model built as a bare struct literal (which is how the layout tests
// and several call sites build one). 80x24 is the floor every terminal meets.
const (
	fallbackWidth  = 80
	fallbackHeight = 24
)

type headerKind int

const (
	hdrNone    headerKind = iota // no chrome above the body at all
	hdrCompact                   // exactly one row, at every width
	hdrFull                      // gauge + axes strip + delta line
)

// header is what a mode asks for. right fills the compact tier's third slot
// with a mode marker ("FIX PREVIEW"); when it is empty the slot falls back to
// naming the weakest axes, so the row is never wasted.
type header struct {
	kind  headerKind
	right string
}

func noHeader() header                  { return header{kind: hdrNone} }
func compactHeader(right string) header { return header{kind: hdrCompact, right: right} }
func fullHeader() header                { return header{kind: hdrFull} }

// compose renders one whole screen, and is the only place a frame is
// assembled.
//
//	hdr    which header tier the mode wants. compose may downgrade hdrFull
//	       when the screen is too short to spend the rows on it.
//	title  extra chrome rows under the header — a modal's label. Already
//	       styled.
//	hint   key bindings for the footer, which is pinned to the last row.
//	fill   draws the body. Called exactly once, with the number of rows it
//	       may use. Returning fewer pads the bottom; returning more is cut.
//
// The result is exactly m.height lines with no trailing newline. The trailing
// newline matters: the height test counts separators, so one stray "\n" makes
// the frame h+1 rows and scrolls the alt screen.
func (m *appModel) compose(hdr header, title []string, hint string, fill func(rows int) []string) string {
	m.fitSize()
	w, h := m.width, m.height

	// The footer is costed first because it is the one region that must
	// survive: it is where every key binding is documented, and a user who
	// cannot see it has no way to find out what to press.
	ftr := m.footerRows(hint)

	top := m.headerRows(hdr, len(ftr))
	top = append(top, title...)
	if len(top) > 0 {
		top = append(top, m.ruleRow())
	}

	// Shed chrome from the bottom of the header up — the rule first, then the
	// delta line, then axis rows — rather than clipping the frame, so what is
	// lost is always the least informative thing left.
	for len(top)+len(ftr) > h && len(top) > 0 {
		top = top[:len(top)-1]
	}
	if len(ftr) > h {
		ftr = ftr[len(ftr)-h:] // keep the hints, drop the footer's rule
	}

	budget := h - len(top) - len(ftr)
	body := fitRows(fill(budget), budget)

	out := make([]string, 0, h)
	out = append(out, top...)
	out = append(out, body...)
	out = append(out, ftr...)
	for i := range out {
		out[i] = clip(out[i], w)
	}
	return strings.Join(out, "\n")
}

// fitSize substitutes a usable terminal size for an unset one. Without it a
// model that has not seen a WindowSizeMsg draws with width 0, which means
// strings.Repeat with a negative count and a negative row budget.
func (m *appModel) fitSize() {
	if m.width <= 0 {
		m.width = fallbackWidth
	}
	if m.height <= 0 {
		m.height = fallbackHeight
	}
}

// headerRows renders the requested tier, downgrading hdrFull when the axes
// strip would not leave the body enough room. footerRows is how tall the
// footer turned out to be; the decision needs it, and only compose knows.
func (m *appModel) headerRows(hdr header, footerRows int) []string {
	switch hdr.kind {
	case hdrNone:
		return nil
	case hdrFull:
		// Two tiers of full header, then the compact row. The coverage
		// notices are the part that varies with the host rather than with
		// the design — a host with no Docker, no Trivy and no systemd
		// contributes three rows the same screen did not have to find on the
		// developer's laptop — so they are given up before the axes strip
		// they annotate, instead of taking the whole header down with them.
		full := m.fullHeaderRows()
		if m.height-len(full)-1-footerRows >= minBodyRows {
			return full
		}
		if bare := m.fullHeaderRowsWithout(coverage); m.height-len(bare)-1-footerRows >= minBodyRows {
			return bare
		}
	}
	return []string{m.topRow(hdr.right)}
}

// headerPart names an optional region of the full header, for the callers
// that build it without one.
type headerPart int

const coverage headerPart = iota

// fullHeaderRows is the list's header, in the order the dashboard stacks the
// same information: the brand and exposure gauge, the per-axis bars, what
// moved since the last scan, then which domains did not fully cover their
// ground.
func (m *appModel) fullHeaderRows() []string {
	return m.fullHeaderRowsWithout(-1)
}

func (m *appModel) fullHeaderRowsWithout(omit headerPart) []string {
	s := m.sty()
	out := []string{s.dim.Render(m.gl.Of(glyph.Brand)+" ") + s.brand.Render("hostveil") + "   " +
		m.gaugeRow(gaugeMeterWidth(m.width))}
	// How the breakdown is drawn is the arrangement's call: the strip, one
	// spark row, or nothing at all where the rail is carrying the same
	// numbers with the reason for each gap attached.
	switch m.axesStyle() {
	case axesFull:
		if ax := m.axesLine(); ax != "" {
			out = append(out, strings.Split(ax, "\n")...)
		}
	case axesSpark:
		if ax := m.sparkAxesLine(m.width); ax != "" {
			out = append(out, ax)
		}
	case axesNone:
	}
	if d := m.deltaLine(); d != "" {
		out = append(out, d)
	}
	if omit != coverage {
		out = append(out, m.coverageRows()...)
	}
	return out
}

// topRow is the compact tier: one row, at every width, ever.
//
// Four segments joined by three spaces. When they do not fit, the meter is
// squeezed before anything is dropped, and only then are segments dropped
// right to left — the brand is what identifies the program and is never one
// of them.
func (m *appModel) topRow(right string) string {
	s := m.sty()
	brand := s.dim.Render(m.gl.Of(glyph.Brand)+" ") + s.brand.Render("hostveil")

	if right == "" {
		right = m.axisDigest()
	}
	var segs []string
	if right != "" {
		segs = append(segs, s.dim.Render(right))
	}
	if d := m.deltaDigest(); d != "" {
		segs = append(segs, d)
	}

	const gap = "   "
	for n := len(segs); n >= 0; n-- {
		for mw := 18; mw >= 4; mw -= 2 {
			row := brand + gap + m.gaugeRow(mw)
			for _, sg := range segs[:n] {
				row += gap + sg
			}
			if lipgloss.Width(row) <= m.width {
				return row
			}
		}
	}
	return brand // not even the gauge fits; clip() guards the rest
}

// gaugeRow is "SECURITY ▊▊▊░░ 62/100" with a meter of the given width. The
// literal SECURITY is deliberate and load-bearing: it is how both header
// tiers stay recognisably the same instrument.
func (m *appModel) gaugeRow(meterW int) string {
	s := m.sty()
	// A report where no domain ran has no score to draw. An empty meter
	// beside a number would read as "0/100 — terrible host" rather than
	// "nothing was examined", which are opposite messages.
	if m.report.Domains != nil && !m.report.Score.Applicable {
		return s.dim.Render("SECURITY ") + s.dim.Render("N/A — nothing could be scanned")
	}
	sc := m.report.Score.Overall
	return s.dim.Render("SECURITY ") + s.meter(sc, meterW, s.band(sc)) +
		s.bone.Render(fmt.Sprintf(" %d", sc)) + s.dim.Render("/100")
}

// gaugeMeterWidth shrinks the full header's meter on a narrow terminal.
// Everything around it is fixed width: "▚ " + "hostveil" + a three-space gap
// + "SECURITY " + " NNN" + "/100".
func gaugeMeterWidth(w int) int {
	const chrome = 2 + 8 + 3 + 9 + 4 + 4
	if w > 0 && w-chrome < 18 {
		return max(4, w-chrome)
	}
	return 18
}

// axisDigest names the two weakest applicable axes. It is the compact tier's
// stand-in for the strip: not the whole breakdown, but enough to say where
// the score is being lost without spending nine rows saying it.
func (m *appModel) axisDigest() string {
	var ax []model.ScoreAxis
	for _, a := range m.report.Score.Axes {
		if a.Applicable {
			ax = append(ax, a)
		}
	}
	if len(ax) == 0 {
		return ""
	}
	// Stable, so ties keep axisDefs order and the digest does not flicker
	// between two equally weak domains.
	sort.SliceStable(ax, func(i, j int) bool { return ax[i].Score < ax[j].Score })
	if len(ax) > 2 {
		ax = ax[:2]
	}
	parts := make([]string, 0, len(ax))
	for _, a := range ax {
		parts = append(parts, fmt.Sprintf("%s %d", a.ID, a.Score))
	}
	return "weakest " + strings.Join(parts, " · ")
}

// deltaDigest is deltaLine compressed into one field for the compact tier.
func (m *appModel) deltaDigest() string {
	if !m.delta.HasChanges() {
		return ""
	}
	s := m.sty()
	var parts []string
	if n := len(m.delta.Resolved); n > 0 {
		parts = append(parts, s.safe.Render(m.gl.Of(glyph.OK)+strconv.Itoa(n)))
	}
	if n := len(m.delta.New); n > 0 {
		parts = append(parts, lipgloss.NewStyle().Foreground(s.cHigh).Render(fmt.Sprintf("+%d", n)))
	}
	if n := len(m.delta.Changed); n > 0 {
		parts = append(parts, s.bone.Render(fmt.Sprintf("~%d", n)))
	}
	return strings.Join(parts, " ")
}

// footerRows is the pinned footer: a rule, then the key hints reflowed to the
// terminal width. An empty hint pins nothing.
func (m *appModel) footerRows(hint string) []string {
	if hint == "" {
		return nil
	}
	dim := m.sty().dim
	out := []string{m.ruleRow()}
	for _, line := range strings.Split(m.wrapHint(hint), "\n") {
		out = append(out, dim.Render(line))
	}
	return out
}

func (m *appModel) ruleRow() string {
	w := m.width
	if w < 1 {
		w = 1
	}
	return m.sty().track.Render(strings.Repeat("─", w))
}

// --- row plumbing ---

// styledRows renders each line of a multi-line string separately, so the
// result can be laid out by the frame rather than embedded as one blob. An
// empty string is no rows at all, not one empty row — the difference is a
// stray blank line in every frame that uses it.
func styledRows(st lipgloss.Style, text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = st.Render(l)
	}
	return out
}

// fitRows pads with blank rows or cuts from the end so the result is exactly
// n rows. Padding is "" rather than spaces: it satisfies the width invariant
// for free, and the background is already painted by tea.View.
func fitRows(rs []string, n int) []string {
	if n <= 0 {
		return nil
	}
	if len(rs) >= n {
		return rs[:n]
	}
	out := make([]string, n)
	copy(out, rs)
	return out
}

// centerRows pads to n rows with the blanks split above and below, so a short
// body sits in the middle of the frame instead of clinging to the top of it.
func centerRows(rs []string, n int) []string {
	if n <= 0 || len(rs) >= n {
		return fitRows(rs, n)
	}
	out := make([]string, n)
	copy(out[(n-len(rs))/2:], rs)
	return out
}

// clipRows is fitRows for a body that may genuinely be longer than the frame.
// The last kept row becomes an ellipsis, because a body cut without a mark
// reads as the end of the text rather than the end of the screen.
func (m *appModel) clipRows(rs []string, n int) []string {
	if n <= 0 {
		return nil
	}
	if len(rs) <= n {
		return rs
	}
	out := make([]string, n)
	copy(out, rs[:n])
	out[n-1] = m.sty().dim.Render("  …")
	return out
}

// clip hard-cuts one rendered row to w columns, counting printable cells and
// copying escape sequences through at zero width. It is the frame's last-
// resort width guarantee.
//
// truncate() cannot do this job: it measures runes and would count an SGR
// sequence as a dozen columns, then cut through the middle of one. The two
// are for different things — truncate shortens plain text before it is
// styled, clip bounds a row that already is.
func clip(s string, w int) string {
	if w <= 0 {
		return ""
	}
	var b strings.Builder
	col, styled := 0, false
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++
			}
			b.WriteString(s[i:j])
			styled = true
			i = j
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		rw := lipgloss.Width(string(r))
		if col+rw > w {
			if styled {
				b.WriteString("\x1b[m") // never leave a colour open past the cut
			}
			return b.String()
		}
		b.WriteString(s[i : i+size])
		col += rw
		i += size
	}
	return s
}
