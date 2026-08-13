package tui

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/glyph"
	"github.com/seolcu/hostveil/internal/model"
)

// This file draws the regions the arrangements need. Everything here is a
// terminal translation of something the dashboard's stylesheet does: the
// verdict band, the domain rail, the spark strip, the severity lanes, the
// inline detail, and the column joining that puts two of them side by side.
//
// The default arrangement uses the rail and the joiner; A · Split uses the
// joiner alone.

// Column geometry. The dashboard collapses to one column below 820px; a
// terminal has to make the same call in characters, and the numbers below
// are what the regions actually need rather than a scaled-down guess.
//
// minListWidth is the one that decides: a findings row is a severity label,
// a 13-column id and a title, and under about forty columns the title is
// gone and the list has stopped being a list. So the pane is given back
// before the rail is, and both are given back before the list is squeezed.
const (
	railWidth         = 24
	minRailTotalWidth = 76
	minPaneWidth      = 34
	maxPaneWidth      = 52
	minPaneTotalWidth = 100
	minListWidth      = 40
)

// bodyColumns divides the terminal between the rail, the list and the pane.
// A width of 0 means that column is not drawn at all. The returned widths
// plus one separator column between each add up to exactly m.width, which is
// what keeps the joined rows inside the frame.
func (m *appModel) bodyColumns() (rail, list, pane int) {
	// The separator is one column wide, or two where the terminal draws East
	// Asian Ambiguous characters wide and the operator has said so. Costing it
	// as one either way put every column one to the left of where the rules
	// above them were drawn.
	sep := sepWidth()
	list = m.width
	if m.wantsRail() && m.width >= minRailTotalWidth {
		rail = railWidth
		list -= rail + sep
	}
	// No findings, nothing to show beside them. The pane would be forty
	// columns of "Nothing to show." taken from the one message that matters
	// on an empty list — and that message is the long one, the one that says
	// how many domains could not be looked at. The rail stays: on a host
	// where nothing could be scanned it is the only thing that says why.
	if m.wantsPane() && len(m.active) > 0 && m.width >= minPaneTotalWidth {
		p := clamp(m.width*2/5, minPaneWidth, maxPaneWidth)
		if list-p-sep >= minListWidth {
			pane = p
			list -= pane + sep
		}
	}
	return rail, list, pane
}

// joinColumns lays rendered columns side by side, separated by a vertical
// rule, and returns exactly n rows.
//
// Each cell is clipped before it is padded: the columns are already styled,
// so a cell that overran would push every column to its right off the
// terminal, and clip is the only thing in this package that can bound a
// styled row without cutting through an escape sequence.
func (m *appModel) joinColumns(n int, widths []int, cols [][]string) []string {
	track := m.sty().track
	out := make([]string, n)
	for i := range n {
		cells := make([]string, len(widths))
		for c, w := range widths {
			cell := ""
			if i < len(cols[c]) {
				cell = cols[c][i]
			}
			cells[c] = padRight(clip(cell, w), w)
		}
		var b strings.Builder
		for c, cell := range cells {
			if c > 0 {
				b.WriteString(track.Render(junction(cells[c-1], cell)))
			}
			b.WriteString(cell)
		}
		out[i] = b.String()
	}
	return out
}

// junction picks the character that joins two cells: the vertical rule, or a
// tee where one of them ends or begins with a horizontal rule of its own.
//
// The detail pane closes with a rule above its actions and the verdict band
// closes with one under its sentence, and both of those meet the separator
// beside them. Drawn as a plain │ the result is a line that visibly stops one
// column short of the one it is supposed to meet — the terminal equivalent of
// a border that does not quite reach the corner, and the thing that made this
// interface look drawn rather than composed.
func junction(left, right string) string {
	l := endsWithRule(left)
	r := beginsWithRule(right)
	switch {
	case l && r:
		return "┼"
	case l:
		return "┤"
	case r:
		return "├"
	}
	return "│"
}

func endsWithRule(cell string) bool {
	rs := visibleRunes(cell)
	return len(rs) > 0 && rs[len(rs)-1] == '─'
}

func beginsWithRule(cell string) bool {
	rs := visibleRunes(cell)
	return len(rs) > 0 && rs[0] == '─'
}

// visibleRunes drops the escape sequences from a styled row, so a caller can
// ask what is actually drawn in a given column.
func visibleRunes(s string) []rune {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		out = append(out, r)
		i += size
	}
	return out
}

// --- verdict band (B · Triage, G · Rail + verdict) ---

// verdictRows is the dashboard's verdict band: what is wrong, in a sentence,
// with the action beside it.
//
// The headline is a claim the scan can defend. With nothing scannable there
// is no claim to make, which is the same reason the gauge refuses a number —
// "nothing exposed" and "nobody looked" are opposite readings and this is
// the one row on the screen big enough to be read as the answer.
//
// The wording comes from model.Band.Verdict rather than from a table here,
// so the sentence and the meter beside it cannot disagree about which band
// the host is in.
func (m *appModel) verdictRows(w int) []string {
	s := m.sty()
	all := m.report.Select(model.Filter{})

	high, autos := 0, 0
	for _, f := range all {
		if f.Severity == model.SeverityHigh {
			high++
		}
		if f.Remediation == model.RemediationAuto {
			autos++
		}
	}

	var head string
	var headC = s.cBone
	switch {
	case m.report.Domains != nil && !m.report.Score.Applicable:
		head = "This host could not be scanned."
		headC = s.cHigh
	case high > 0:
		head = fmt.Sprintf("%d finding%s reachable right now.", high,
			map[bool]string{true: " is", false: "s are"}[high == 1])
		headC = s.cCrit
	default:
		head = "This host is " + model.BandFor(m.report.Score.Overall).Verdict() + "."
	}

	scored := 0
	for _, ax := range m.report.Score.Axes {
		if ax.Applicable {
			scored++
		}
	}
	stat := fmt.Sprintf("%d unresolved · %d of %d domains scored",
		len(all), scored, len(m.report.Score.Axes))
	if gaps := m.report.IncompleteDomains(); gaps > 0 {
		stat += fmt.Sprintf(" · %d could not be fully checked", gaps)
	}

	// The note beside the action is the first thing to go when the band is
	// narrower than the sentence: dropped whole rather than left for the frame
	// to cut, which ended a reassurance about backups mid-word — "reversible
	// from histo" — in the one place on the screen that exists to reassure.
	act := s.dim.Render(truncate("Nothing here can be fixed unattended.", w))
	if autos > 0 {
		lead := fmt.Sprintf("a  fix %d safe finding%s", autos,
			map[bool]string{true: "", false: "s"}[autos == 1])
		const note = "   each is previewed, backed up, and reversible from history"
		act = s.safe.Render(truncate(lead, w))
		if len(lead)+len(note) <= w {
			act += s.dim.Render(note)
		}
	}

	return []string{
		lipgloss.NewStyle().Foreground(headC).Bold(true).Render(truncate(head, w)),
		s.dim.Render(truncate(stat, w)),
		act,
		m.ruleRow(),
	}
}

// --- domain rail (C · Console, G · Rail + verdict) ---

// railRows is every axis as a row: the score, a bar, the severity mix under
// it, and for a domain that did not run, the reason instead of a number.
//
// It replaces the axes strip where it appears, and it is the only place in
// those arrangements where a skipped domain is both visible and explained —
// which is the bet: the strip says a number is missing, the rail says
// whether the host has no Docker, or the daemon refused, or the scan ran as
// a user who cannot read the socket.
//
// Two densities. With room it spends a second row per domain on the mix or
// the reason, which is what makes it more than a vertical strip; without, it
// drops to one row each and then to a truncated list, because the rail
// losing its tail is better than the rail pushing the findings out.
func (m *appModel) railRows(w, budget int) []string {
	s := m.sty()
	axes := m.report.Score.Axes
	if len(axes) == 0 || budget <= 0 {
		return nil
	}

	all := m.report.Select(model.Filter{})
	byDomain := map[model.Source][]model.Finding{}
	for _, f := range all {
		byDomain[f.Source] = append(byDomain[f.Source], f)
	}
	reason := map[model.Source]string{}
	state := map[model.Source]model.ScanState{}
	for _, d := range m.report.Domains {
		reason[d.Source], state[d.Source] = d.Reason, d.State
	}

	// Dense spends a second row per domain on the severity mix. A domain that
	// did not run gets its second row either way, because that row is the
	// reason — and "N/A" with nothing next to it is the unexplained gap the
	// rail was added to close. It never fit otherwise: twelve domains need 25
	// rows to go dense and a 30-row terminal leaves the body about 20, so on
	// every real host the reason was the thing that dropped out, in the one
	// arrangement whose whole claim is that it carries it.
	dense := 1+2*len(axes) <= budget
	compactMix := m.mixIsCompact(byDomain, w-4)

	// Airy spends one more row per domain on the gap between them.
	//
	// Dense packs twelve domains into twenty-four rows with nothing between
	// any two, and the first thing said about it was that the column is hard
	// to read — which it is: the eye has to work out for itself that a name
	// and the counts under it are one thing while the next name is another.
	// The indent under each name says so, and a blank line says it louder for
	// the price of a row.
	//
	// Only when the rows are actually there. This is the third tier of the
	// same budget the two above it come out of, so a terminal that cannot
	// afford it keeps every domain and loses the gaps rather than the other
	// way round: head + 2 rows each + one gap between each pair.
	airy := dense && 3*len(axes) <= budget

	// Built per domain and flattened afterwards, so a rail that does not fit
	// is cut between domains and can say how many whole ones it dropped. Cut
	// by row instead and the tail lands mid-domain: a score with the mix that
	// belongs to it missing reads as a domain with no findings.
	blocks := make([][]string, 0, len(axes))
	for _, ax := range axes {
		on := m.filter.Source == ax.Source
		name := sourceLabel(ax.Source)

		// "› " marks the domain the list is filtered to, in text as well as in
		// the fill, for the same reason the chips carry their count: an
		// attribute does not survive a screenshot or a pipe.
		marker := "  "
		if on {
			marker = s.accent.Render(m.gl.Of(glyph.Cursor) + " ")
		}

		val := "N/A"
		valStyle := s.dim
		switch {
		case !ax.Applicable:
		case ax.Degraded:
			val, valStyle = strconv.Itoa(int(ax.Score))+"~", s.bone
		default:
			val, valStyle = strconv.Itoa(int(ax.Score)), s.bone
		}

		// name + meter + value, right-aligned value so the column reads down.
		const valW = 4
		meterW := 6
		nameW := w - 2 - meterW - 1 - valW
		if nameW < 4 {
			nameW, meterW = max(1, w-2-valW), 0
		}
		row := marker
		nm := padRight(truncate(name, nameW), nameW)
		if on {
			row += s.sel.Render(nm)
		} else if ax.Applicable {
			row += s.bone.Render(nm)
		} else {
			row += s.dim.Render(nm)
		}
		if meterW > 0 {
			// An axis that did not run gets an empty bar, not a bar of its
			// score: a skipped domain carries whatever Score a zero value
			// leaves behind, and drawn it came out full — a solid meter beside
			// the letters N/A, which is the "I could not look" / "nothing
			// there" confusion the whole scanner is built to refuse.
			pct, c := uint8(0), s.cLine
			if ax.Applicable {
				pct, c = min(ax.Score, 100), s.band(ax.Score)
			}
			row += " " + s.meterAtLeastOne(pct, meterW, c, ax.Applicable)
		}
		// The number takes its band's color rather than plain bone. A meter
		// six cells wide cannot separate 0 from 8, and those are the domains
		// worth looking at first; the digits can, and they are already there.
		if ax.Applicable {
			valStyle = lipgloss.NewStyle().Foreground(s.band(ax.Score))
		}
		row += valStyle.Render(fmt.Sprintf("%*s", valW, val))

		block := []string{row}
		switch {
		case !ax.Applicable:
			block = append(block, s.dim.Render(truncate("  "+strings.ToLower(state[ax.Source].String())+
				" — "+reasonOr(reason[ax.Source], "did not run"), w)))
		case dense:
			// The per-axis headroom rides on the mix row rather than the
			// score row: the rail is about twenty columns wide and the score
			// row has none to spare, while the mix row is usually eight
			// characters of "3H·1M·6L" in twenty. Compact, because this
			// column is a glance and the exact arithmetic is a keypress away.
			// Indented one step past the domain name it belongs to. The rail
			// is twelve domains of two rows each with nothing between them,
			// and at the same indent the pairs did not read as pairs — the
			// mix line looked like another domain whose name happened to be a
			// list of numbers. Two columns is the cheapest hierarchy there
			// is, and the only one the row budget can afford.
			mix := m.severityMix(byDomain[ax.Source], w-4, compactMix)
			if ax.Applicable && ax.AfterFixes > ax.Score {
				// A literal arrow, not a glyph row: internal/glyph records why
				// it has none, and "›" is already the rail's own marker for
				// the domain the list is filtered to. One symbol meaning two
				// things in one column is worse than a character the plain
				// set does not own.
				if note := s.dim.Render(fmt.Sprintf(" →%d", ax.AfterFixes)); lipgloss.Width(mix)+lipgloss.Width(note)+4 <= w {
					mix += note
				}
			}
			block = append(block, "    "+mix)
		}
		blocks = append(blocks, block)
	}

	// The dashboard's rail head reads "Domains · 15 findings", and the count
	// is the findings rather than the domains — which is worth keeping,
	// because the rail is a list of domains and a header counting them again
	// would say nothing the rows below it do not.
	head := fmt.Sprintf("DOMAINS · %d findings", len(all))
	if lipgloss.Width(head) > w {
		head = fmt.Sprintf("DOMAINS · %d", len(all))
	}
	out := []string{s.accent.Render(truncate(head, w))}
	for i, b := range blocks {
		if airy && i > 0 {
			b = append([]string{""}, b...)
		}
		// Truncating the rail is the last resort, and it says so: a rail that
		// simply stopped would read as a host with six domains.
		if len(out)+len(b) > budget {
			if len(out) < budget {
				out = append(out, s.dim.Render(truncate(fmt.Sprintf("%s %d more", m.gl.Of(glyph.Skipped), len(blocks)-i), w)))
			}
			break
		}
		out = append(out, b...)
	}
	return out
}

// severityMix is a domain's findings as one line of counts, in the model's
// most-severe-first order, each in its own color. A domain with none says so
// rather than rendering an empty row that reads as a rendering fault.
//
// Two spellings of the same line. The dashboard writes "3 high · 1 med · 2
// low" and that is what goes here wherever it fits — at the rail's 24 columns
// the worst case is exactly the 22 it has, which is not a coincidence, it is
// what the rail was widened to hold. Below that it falls back to "3H·1M·2L",
// because a mix cut off after "3 high · 1 m" has lost the count it was
// drawn for, and one letter per level still reads.
func (m *appModel) severityMix(fs []model.Finding, w int, compact bool) string {
	s := m.sty()
	if len(fs) == 0 {
		return s.dim.Render(truncate("clean", w))
	}

	// Dropped between terms, never through one — the same call the chip row
	// makes, and for the same reason: a truncated label is obviously
	// truncated, while a truncated *count* is a different number. Clipping the
	// joined row left "9 high · 16 med · 28", which reports 28 of a severity
	// it does not name and says nothing at all about the one it cut.
	//
	// The terms are in most-severe-first order, so what falls off the end is
	// the level that matters least.
	parts, sep := m.severityMixParts(fs, compact), s.dim.Render(" · ")
	if compact {
		sep = s.dim.Render("·")
	}
	row := ""
	for i, p := range parts {
		cand := p
		if i > 0 {
			cand = sep + p
		}
		if lipgloss.Width(row)+lipgloss.Width(cand) > w {
			break
		}
		row += cand
	}
	return row
}

// severityMixRow builds the line without fitting it to anything, which is the
// only form the width of it can be asked about.
//
// Split out because folding the clip into the builder made the question
// unanswerable: mixIsCompact measured a string that had already been cut to
// the width it was being compared against, so it was never wider, the rail
// never fell back, and a mix that did not fit was drawn cut off after
// "9 high · 16 med · 28" — a count truncated into a different number, which is
// the one thing this line exists to report.
func (m *appModel) severityMixRow(fs []model.Finding, compact bool) string {
	s := m.sty()
	if compact {
		return strings.Join(m.severityMixParts(fs, true), s.dim.Render("·"))
	}
	return strings.Join(m.severityMixParts(fs, false), s.dim.Render(" · "))
}

// severityMixParts is one styled term per severity present, most severe
// first. Kept apart from the joining so the row can be assembled a term at a
// time when it has to be cut.
func (m *appModel) severityMixParts(fs []model.Finding, compact bool) []string {
	s := m.sty()
	counts := map[model.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}

	var parts []string
	for _, sev := range model.AllSeverities() {
		n := counts[sev]
		if n == 0 {
			continue
		}
		st := lipgloss.NewStyle().Foreground(s.severityColor(sev))
		if compact {
			parts = append(parts, st.Render(strconv.Itoa(n)+string([]rune(sevAbbr(sev))[0])))
			continue
		}
		parts = append(parts, st.Render(fmt.Sprintf("%d %s", n, strings.ToLower(sevAbbr(sev)))))
	}
	return parts
}

// mixIsCompact decides the spelling once for the whole rail, rather than each
// domain choosing for itself.
//
// Deciding per domain is what shipped, and it made the rail's *first* row the
// odd one out on every host that has one: the busiest domain has the widest
// counts, so it was the one that overflowed and fell back, and the top of the
// column read "9H·16M·28L" over eleven rows of "2 high · 1 med · 3 low". The
// eye reads a column by its shape, and one row in a different shape reads as a
// different kind of thing rather than as the same thing abbreviated.
func (m *appModel) mixIsCompact(byDomain map[model.Source][]model.Finding, w int) bool {
	for _, fs := range byDomain {
		if len(fs) == 0 {
			continue // "clean" is one word and fits wherever the counts would
		}
		if lipgloss.Width(m.severityMixRow(fs, false)) > w {
			return true
		}
	}
	return false
}

// --- spark strip (B · Triage, I · Inline) ---

// sparkAxesLine is the axes strip compressed into one row: every domain's
// label and score, no meters.
//
// The bet these two arrangements make is that the breakdown is context and
// the list is the work, so the breakdown gets one row rather than three.
// Axes that do not fit are dropped from the right and marked, rather than
// the row being wrapped — wrapping it would spend exactly the rows this is
// here to save.
func (m *appModel) sparkAxesLine(w int) string {
	s := m.sty()
	if len(m.report.Score.Axes) == 0 || w <= 0 {
		return ""
	}
	sep := s.track.Render(" │ ")
	var row string
	shown := 0
	for _, ax := range m.report.Score.Axes {
		val := "N/A"
		c := s.cSlate
		switch {
		case !ax.Applicable:
		case ax.Degraded:
			val, c = strconv.Itoa(int(ax.Score))+"~", s.band(ax.Score)
		default:
			val, c = strconv.Itoa(int(ax.Score)), s.band(ax.Score)
		}
		cell := s.dim.Render(sourceLabel(ax.Source)+" ") + lipgloss.NewStyle().Foreground(c).Bold(true).Render(val)
		cand := cell
		if shown > 0 {
			cand = row + sep + cell
		}
		// Four columns kept back for the "  +N" tail, so the marker never has
		// to be the thing that gets clipped.
		if lipgloss.Width(cand) > w-4 && shown > 0 {
			return row + s.dim.Render(fmt.Sprintf("  +%d", len(m.report.Score.Axes)-shown))
		}
		row, shown = cand, shown+1
	}
	return row
}

// --- severity lanes (H · Lanes) ---

// laneHeadRow is one lane's header: the severity, how many are in it, and
// how many of those hostveil can fix on its own.
//
// The dashboard puts a button here that marks the lane's Auto findings and
// hands them to the batch bar. A terminal has no button, so the same action
// is a key — `m` marks every Auto finding at the cursor's severity — and the
// header says so, because a lane action nobody can find is not an action.
//
// It selects; it does not apply. The dashboard's button says "Select the N
// safe" for the same reason, and the two have to agree: this is one
// arrangement with two renderers, not two arrangements.
func (m *appModel) laneHeadRow(sev model.Severity, n, autos, w int) string {
	s := m.sty()
	c := s.severityColor(sev)
	head := lipgloss.NewStyle().Foreground(c).Bold(true).Render(strings.ToUpper(sev.String()))
	head += s.dim.Render(fmt.Sprintf("  %d", n))
	if autos > 0 {
		head += s.dim.Render("   ") + s.safe.Render(fmt.Sprintf("%d fix themselves", autos)) +
			s.dim.Render("  (m selects them)")
	} else {
		head += s.dim.Render("   none fix themselves")
	}
	return clip(lipgloss.NewStyle().Foreground(c).Render("▌")+head, w)
}

// --- inline detail (I · Inline) ---

// maxInlineRows bounds the block that opens under the cursor. The dashboard
// can let an inline panel grow and scroll the page; here it would push the
// rest of the list off a screen that is already only twenty-odd rows, so the
// block is capped and `enter` still opens the full-screen detail.
const maxInlineRows = 10

// inlineRows is the cursor's finding opened in place: the same text the
// detail view shows, indented under the row it belongs to and bounded.
func (m *appModel) inlineRows(w int) []string {
	if len(m.active) == 0 {
		return nil
	}
	s := m.sty()
	f := m.active[m.cursor]
	body := m.detailBodyRows(f, w-4)

	out := make([]string, 0, len(body)+1)
	for _, r := range body {
		out = append(out, s.track.Render("  │ ")+r)
	}
	if len(out) > maxInlineRows {
		out = out[:maxInlineRows]
		out[maxInlineRows-1] = s.track.Render("  │ ") + s.dim.Render("… enter for the rest")
	}
	if f.IsFixable() {
		out = append(out, s.track.Render("  │ ")+s.safe.Render("f  preview and apply the fix"))
	}
	return out
}
