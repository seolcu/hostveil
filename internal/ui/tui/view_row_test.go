package tui

import (
	lipgloss "charm.land/lipgloss/v2"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func rowFinding(id, service string, r model.RemediationKind) model.Finding {
	return model.NewFinding(id, "Datastore exposed on all network interfaces",
		model.SeverityHigh, model.SourceCompose, r,
		model.WithService(service))
}

// The list row says which of the four kinds a finding is.
//
// It did not, and the only signal was the pick marker — a dot drawn on Auto
// rows and nothing at all on the other three. So Review, Manual and
// Unavailable were indistinguishable from each other in the list, and the
// operator had to open a finding to learn whether there was anything to press.
func TestTheListRowNamesTheRemediationKind(t *testing.T) {
	m := &appModel{width: 120, selected: map[string]bool{}}
	for _, tc := range []struct {
		kind model.RemediationKind
		want string
	}{
		{model.RemediationAuto, "AUTO"},
		{model.RemediationReview, "REVIEW"},
		{model.RemediationManual, "MANUAL"},
		{model.RemediationUnavailable, "N/A"},
	} {
		f := rowFinding("compose.ds018", "cloud/redis", tc.kind)
		m.active = []model.Finding{f}
		for _, cursor := range []bool{false, true} {
			got := plain(m.findingRow(f, cursor, 120))
			if !strings.Contains(got, tc.want) {
				t.Errorf("kind %v, cursor=%v: row does not say %q:\n%q",
					tc.kind, cursor, tc.want, got)
			}
		}
	}
}

// The cursor row keeps the service name.
//
// It used to lose it. findingRow had two branches that each laid the row out
// themselves, and the cursor branch simply did not append the suffix — so
// moving onto a row erased the one column saying which container it was about,
// on the row the operator was by definition looking at. The two branches now
// share the layout and differ only in styling.
func TestTheCursorRowStillNamesItsService(t *testing.T) {
	m := &appModel{width: 120, selected: map[string]bool{}}
	f := rowFinding("compose.ds018", "jellyfin/jellyfin", model.RemediationReview)
	m.active = []model.Finding{f}

	for _, cursor := range []bool{false, true} {
		got := plain(m.findingRow(f, cursor, 120))
		if !strings.Contains(got, "(jellyfin/jellyfin)") {
			t.Errorf("cursor=%v: the row does not name its service:\n%q", cursor, got)
		}
	}
}

// No row overruns the column it was budgeted into, whatever the service name
// happens to be.
//
// The cursor row is padded to the full width on purpose — the selection bar
// has to span the column rather than stopping where the text does — so the
// two are not the same length, and the invariant is the ceiling rather than
// equality. The ceiling is the one that matters: a row wider than its column
// pushes every column right of it off the screen, and the service name is
// host-supplied so it has no safe upper bound.
// Measured with lipgloss.Width, not len([]rune(...)).
//
// A rune count used as a column budget is the exact fault this test exists to
// catch, and it was how this test measured: under RUNEWIDTH_EASTASIAN the
// row's ▌ and ░ are two columns each, so a correct row counted 99 runes for a
// 100-column budget and the test reported the selection bar stopping short.
// It was measuring the wrong thing and reporting the product as broken for it.
func TestNoRowOverrunsItsColumn(t *testing.T) {
	m := &appModel{width: 120, selected: map[string]bool{}}
	const w = 100
	for _, svc := range []string{"", "cloud/redis", strings.Repeat("very-long-", 12)} {
		f := rowFinding("compose.ds018", svc, model.RemediationManual)
		m.active = []model.Finding{f}
		for _, cursor := range []bool{false, true} {
			got := lipgloss.Width(plain(m.findingRow(f, cursor, w)))
			if got > w {
				t.Errorf("service %q, cursor=%v: row is %d columns for a budget of %d",
					svc, cursor, got, w)
			}
		}
		if got := lipgloss.Width(plain(m.findingRow(f, true, w))); got != w {
			t.Errorf("service %q: the cursor row is %d columns, so its selection bar "+
				"stops %d short of the column edge", svc, got, w-got)
		}
	}
}

// TestTheTrendLineFitsTheTerminal.
//
// The sparkline is one glyph per saved scan and the budget is computed in
// scans, which is only the same thing while a glyph is one column. Every bar
// in the ramp is East Asian Ambiguous, so on a terminal that draws that class
// wide the whole line was twice the space allowed for it — the same defect the
// meters had, on the screen that carries the history.
//
// Measured with lipgloss.Width in whichever mode the test runs in, so it is a
// real assertion under RUNEWIDTH_EASTASIAN rather than a tautology.
func TestTheTrendLineFitsTheTerminal(t *testing.T) {
	var trend []model.ScorePoint
	for i := range 200 {
		trend = append(trend, model.ScorePoint{Overall: uint8(i % 101), Applicable: i%7 != 0})
	}
	for _, w := range []int{40, 60, 80, 100, 120, 151, 200} {
		m := &appModel{width: w, trend: trend}
		if got := lipgloss.Width(plain(m.trendLine())); got > w {
			t.Errorf("width %d: the trend line is %d columns", w, got)
		}
	}
}
