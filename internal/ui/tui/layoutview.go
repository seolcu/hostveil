package tui

import (
	"fmt"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/model"
)

// This file draws the regions the alternative arrangements need, and is
// temporary along with layout.go and the picker. Everything here is a
// terminal translation of something the dashboard's stylesheet does: the
// verdict band, the domain rail, the spark strip, the severity lanes, the
// inline detail, and the column joining that puts two of them side by side.
//
// The shipped arrangement uses none of it except the column joiner.

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
	list = m.width
	if m.wantsRail() && m.width >= minRailTotalWidth {
		rail = railWidth
		list -= rail + 1
	}
	// No findings, nothing to show beside them. The pane would be forty
	// columns of "Nothing to show." taken from the one message that matters
	// on an empty list — and that message is the long one, the one that says
	// how many domains could not be looked at. The rail stays: on a host
	// where nothing could be scanned it is the only thing that says why.
	if m.wantsPane() && len(m.active) > 0 && m.width >= minPaneTotalWidth {
		p := clamp(m.width*2/5, minPaneWidth, maxPaneWidth)
		if list-p-1 >= minListWidth {
			pane = p
			list -= pane + 1
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
	sep := m.sty().track.Render("│")
	out := make([]string, n)
	for i := range n {
		var b strings.Builder
		for c, w := range widths {
			if c > 0 {
				b.WriteString(sep)
			}
			cell := ""
			if i < len(cols[c]) {
				cell = cols[c][i]
			}
			b.WriteString(padRight(clip(cell, w), w))
		}
		out[i] = b.String()
	}
	return out
}

// --- verdict band (B · Triage, G · Rail + verdict) ---

// verdictRows is the dashboard's verdict band: what is wrong, in a sentence,
// with the action beside it.
//
// The headline is a claim the scan can defend. With nothing scannable there
// is no claim to make, which is the same reason the gauge refuses a number —
// "no criticals" and "nobody looked" are opposite readings and this is the
// one row on the screen big enough to be read as the answer.
//
// The wording comes from model.Band.Verdict rather than from a table here,
// so the sentence and the meter beside it cannot disagree about which band
// the host is in.
func (m *appModel) verdictRows(w int) []string {
	s := m.sty()
	all := m.report.Select(model.Filter{})

	crit, autos := 0, 0
	for _, f := range all {
		if f.Severity == model.SeverityCritical {
			crit++
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
	case crit > 0:
		head = fmt.Sprintf("%d critical finding%s exposed right now.", crit,
			map[bool]string{true: " is", false: "s are"}[crit == 1])
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

	act := s.dim.Render("Nothing here can be fixed unattended.")
	if autos > 0 {
		act = s.safe.Render(fmt.Sprintf("a  fix %d safe finding%s", autos,
			map[bool]string{true: "", false: "s"}[autos == 1])) +
			s.dim.Render("   each is previewed, backed up, and reversible from history")
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

	dense := 1+2*len(axes) <= budget

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
			marker = s.bone.Render("› ")
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
			row += " " + s.meter(pct, meterW, c)
		}
		row += valStyle.Render(fmt.Sprintf("%*s", valW, val))

		block := []string{row}
		switch {
		case !dense:
		case !ax.Applicable:
			block = append(block, s.dim.Render(truncate("  "+strings.ToLower(state[ax.Source].String())+
				" — "+reasonOr(reason[ax.Source], "did not run"), w)))
		default:
			block = append(block, "  "+m.severityMix(byDomain[ax.Source], w-2))
		}
		blocks = append(blocks, block)
	}

	out := []string{s.dim.Render(truncate(fmt.Sprintf("DOMAINS · %d", len(all)), w))}
	for i, b := range blocks {
		// Truncating the rail is the last resort, and it says so: a rail that
		// simply stopped would read as a host with six domains.
		if len(out)+len(b) > budget {
			if len(out) < budget {
				out = append(out, s.dim.Render(truncate(fmt.Sprintf("· %d more", len(blocks)-i), w)))
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
func (m *appModel) severityMix(fs []model.Finding, w int) string {
	s := m.sty()
	if len(fs) == 0 {
		return s.dim.Render(truncate("clean", w))
	}
	counts := map[model.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for _, sev := range model.AllSeverities() {
		if n := counts[sev]; n > 0 {
			parts = append(parts,
				lipgloss.NewStyle().Foreground(s.severityColor(sev)).
					Render(strconv.Itoa(n)+string([]rune(sevAbbr(sev))[0])))
		}
	}
	return clip(strings.Join(parts, s.dim.Render("·")), w)
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
func (m *appModel) laneHeadRow(sev model.Severity, n, autos, w int) string {
	s := m.sty()
	c := s.severityColor(sev)
	head := lipgloss.NewStyle().Foreground(c).Bold(true).Render(strings.ToUpper(sev.String()))
	head += s.dim.Render(fmt.Sprintf("  %d", n))
	if autos > 0 {
		head += s.dim.Render("   ") + s.safe.Render(fmt.Sprintf("%d fix themselves", autos)) +
			s.dim.Render("  (m marks them)")
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
