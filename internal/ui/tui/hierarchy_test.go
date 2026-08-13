package tui

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// The rail is domains in pairs, and the pairs have to read as pairs.
//
// Twelve domains of two rows each with nothing between any two: an indent
// alone did not do it, because the second row looked like another domain whose
// name happened to be a list of counts, or the word "clean". The branch says
// which row belongs to which name.
//
// Both kinds of second row carry it — the severity mix and the reason a domain
// did not run. They had different indents, two columns and four, so the rail
// drew two depths of hierarchy at once, which is no hierarchy at all.
func TestEverySecondRailRowIsBranchedUnderItsDomain(t *testing.T) {
	m := layoutModel("console", 100, 44)
	rows := m.railRows(railWidth, 44)

	var pairs, branched int
	for i, row := range rows {
		txt := plain(row)
		if strings.TrimSpace(txt) == "" {
			continue
		}
		// A first row carries a score or N/A at its right-hand end; a second
		// row is anything else that follows one.
		if i == 0 || strings.TrimSpace(plain(rows[i-1])) == "" {
			continue
		}
		if !isRailHead(plain(rows[i-1])) || isRailHead(txt) {
			continue
		}
		pairs++
		if strings.HasPrefix(txt, railBranch) {
			branched++
		} else {
			t.Errorf("the row under %q is not branched under it: %q",
				strings.TrimSpace(plain(rows[i-1])), txt)
		}
	}
	if pairs < 4 {
		t.Fatalf("only %d second rows in the rail; the fixture has stopped producing them", pairs)
	}
	// And the branch is something the eye can see. Replacing it with spaces
	// would satisfy a prefix check against the constant while restoring
	// exactly the flat column this exists to fix.
	if strings.TrimSpace(railBranch) == "" {
		t.Error("the branch is whitespace, so the rail is a flat list again")
	}
	if branched != pairs {
		t.Errorf("%d of %d second rows are branched", branched, pairs)
	}
}

// isRailHead reports whether a rail row is a domain's own line: it ends in a
// score or N/A rather than in a mix or a reason.
func isRailHead(txt string) bool {
	fields := strings.Fields(txt)
	if len(fields) == 0 {
		return false
	}
	last := fields[len(fields)-1]
	if last == "N/A" {
		return true
	}
	last = strings.TrimSuffix(last, "~")
	for _, r := range last {
		if r < '0' || r > '9' {
			return false
		}
	}
	return last != ""
}

// The branch is measured in columns, not runes.
//
// "└" is East Asian Ambiguous, so under RUNEWIDTH_EASTASIAN it is two columns
// and the prefix is five. Three budgets are keyed to it — the one that decides
// the mix's spelling for the whole rail, the one that sizes each domain's mix,
// and the gate on the headroom note — and they have to move together, or
// mixIsCompact chooses against a width the render does not have.
func TestTheRailBranchIsBudgetedInColumns(t *testing.T) {
	if got := railBranchW; got != lipgloss.Width(railBranch) {
		t.Errorf("railBranchW = %d, want %d columns", got, lipgloss.Width(railBranch))
	}
	// The branched rows only. A domain's own row carries a meter, and the
	// meter is built from block elements by rune count rather than to a column
	// budget — so under this variable every one of them is over-wide for a
	// reason that predates the branch and belongs to its own fix. See the skip
	// in TestTheHeaderComposesRowsThatFitBeforeTheFrameClipsThem.
	m := layoutModel("console", 100, 44)
	var branched int
	for i, row := range m.railRows(railWidth, 44) {
		if !strings.HasPrefix(plain(row), railBranch) {
			continue
		}
		branched++
		if got := visibleWidth(row); got > railWidth {
			t.Errorf("branched rail row %d is %d columns, the rail is %d: %q", i, got, railWidth, plain(row))
		}
	}
	if branched < 4 {
		t.Fatalf("only %d branched rows measured", branched)
	}
}

// The inline block does not say again what the row above it just said.
//
// It is drawn immediately under the list row for the same finding, and that
// row carries the severity and the id — so the detail view's header repeated
// two of its three lines four columns to the right of where the reader had
// just read them.
//
// What it keeps is what the row above cannot show. The remediation kind is on
// no list row at all (the list marks only whether a finding is Auto-fixable,
// so Review and Manual are indistinguishable there), and the service is
// dropped from the cursor's row specifically — findingRow computes the suffix
// in its non-cursor branch only.
func TestTheInlineBlockDoesNotRepeatTheRowAboveIt(t *testing.T) {
	m := layoutModel("inline", 120, 34)
	m.cursor = 0
	f := m.active[0]

	block := m.inlineRows(120)
	if len(block) == 0 {
		t.Fatal("the inline block is empty")
	}
	body := plain(strings.Join(block, "\n"))

	if strings.Contains(body, strings.ToUpper(f.Severity.String())) {
		t.Errorf("the inline block repeats the severity the row above shows:\n%s", body)
	}
	if strings.Contains(body, strings.ToUpper(f.ID)) {
		t.Errorf("the inline block repeats the id the row above shows:\n%s", body)
	}
	if !strings.Contains(body, strings.ToUpper(f.Remediation.String())) {
		t.Errorf("the inline block drops the remediation kind, which no list row shows:\n%s", body)
	}
	if f.Service != "" && !strings.Contains(body, f.Service) {
		t.Errorf("the inline block drops the service, which the cursor's row does not show:\n%s", body)
	}
}

// And the full-screen detail keeps its header, because there is no row above
// it there. The two share detailFactsRows and nothing else.
func TestTheFullDetailKeepsItsHeader(t *testing.T) {
	m := layoutModel("console", 120, 34)
	m.mode = modeDetail
	m.cursor = 0
	f := m.active[0]

	got := plain(m.View().Content)
	for _, want := range []string{strings.ToUpper(f.Severity.String()), strings.ToUpper(f.ID)} {
		if !strings.Contains(got, want) {
			t.Errorf("the full-screen detail no longer names %q; it has no list row above it to carry that:\n%s", want, got)
		}
	}
}

// The facts stay in one copy across all three renderings. A second copy is a
// second place for the AI box, the how-to, or the why-no-fix note to be
// forgotten — which is what detailBodyRows' own note has said since the pane
// was added.
func TestTheThreeDetailRenderingsShareTheirFacts(t *testing.T) {
	m := layoutModel("console", 120, 34)
	m.cursor = 0
	f := m.active[0]

	facts := plain(strings.Join(m.detailFactsRows(f, 80), "\n"))
	if !strings.Contains(facts, "HOW TO FIX") {
		t.Fatal("the shared facts no longer carry the how-to")
	}
	for name, rows := range map[string][]string{
		"the full-screen detail": m.detailBodyRows(f, 80),
		"the inline block":       m.inlineRows(120),
	} {
		if !strings.Contains(plain(strings.Join(rows, "\n")), "HOW TO FIX") {
			t.Errorf("%s does not carry the shared facts", name)
		}
	}
}
