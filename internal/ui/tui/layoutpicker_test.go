package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/glyph"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/web"
)

// The picker exists to settle which arrangement hostveil keeps, in both
// interfaces at once. So what these tests hold is what makes it usable for
// that: the six here are the same six as the dashboard's, every one of them
// actually changes the screen, choosing none of them leaves the shipped TUI
// exactly as it was, and none of them can push a row past the edge of the
// terminal — which is the one failure a terminal cannot absorb.

// layoutFixture is a host with every severity present, some findings
// hostveil can fix on its own, a skipped domain and a degraded one. The rail
// and the verdict are both summaries, and a fixture missing any of those
// would let a summary pass by having nothing to summarise.
func layoutFixture() model.Report {
	var fs []model.Finding
	add := func(n int, id string, sev model.Severity, rem model.RemediationKind, src model.Source) {
		for i := range n {
			fs = append(fs, model.NewFinding(id, "Datastore exposed on all network interfaces",
				sev, src, rem, model.WithService(fmt.Sprintf("svc-%d", i)),
				model.WithDescription("A database or cache published on 0.0.0.0 is reachable from the internet."),
				model.WithHowToFix("Bind the port to 127.0.0.1 and set a strong password.")))
		}
	}
	add(3, "compose.ds018", model.SeverityHigh, model.RemediationAuto, model.SourceCompose)
	add(5, "compose.ds016", model.SeverityMedium, model.RemediationManual, model.SourceCompose)
	add(7, "ssh.rootlogin", model.SeverityMedium, model.RemediationAuto, model.SourceSSH)
	add(11, "ports.exposed", model.SeverityLow, model.RemediationManual, model.SourcePorts)

	states := map[model.Source]model.ScanState{
		model.SourceCompose: model.ScanDone,
		model.SourceSSH:     model.ScanDone,
		model.SourcePorts:   model.ScanDegraded,
		model.SourceCVE:     model.ScanSkipped,
	}
	return model.Report{
		Findings: fs,
		Score:    model.ScoreReport(fs, states),
		Domains: []model.DomainResult{
			{Source: model.SourceCompose, State: model.ScanDone, FindingCount: 8},
			{Source: model.SourceSSH, State: model.ScanDone, FindingCount: 7},
			{Source: model.SourcePorts, State: model.ScanDegraded, Reason: "the firewall would not answer"},
			{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy is not installed"},
		},
	}
}

func layoutModel(id string, w, h int) *appModel {
	m := &appModel{mode: modeList, width: w, height: h,
		report: layoutFixture(), selected: map[string]bool{}, layout: id}
	m.active = m.report.Select(m.filter)
	return m
}

// The two registries are one registry with two readers. A picker whose "B"
// meant triage in the browser and something else in the terminal would make
// the comparison it exists for worse than no picker at all — and there is
// nothing else in either file that would notice.
//
// The import of internal/ui/web is why this lives in a test: the layering
// check exempts test files, and a UI importing another UI in production code
// would be a genuine violation.
func TestLayoutRegistriesMatchTheDashboard(t *testing.T) {
	got, want := Layouts(), web.Layouts()
	if len(got) != len(want) {
		t.Fatalf("the TUI lists %d arrangements and the dashboard %d", len(got), len(want))
	}
	for i := range got {
		if got[i].ID != want[i].ID || got[i].Name != want[i].Name {
			t.Errorf("position %d: TUI has %q/%q, dashboard has %q/%q",
				i, got[i].ID, got[i].Name, want[i].ID, want[i].Name)
		}
	}
	if DefaultLayout().ID != web.DefaultLayout().ID {
		t.Errorf("defaults differ: TUI %q, dashboard %q", DefaultLayout().ID, web.DefaultLayout().ID)
	}
}

// An operator who never presses `l` must see the arrangement hostveil chose,
// not whichever one happened to be listed first. That is two claims: the
// default is C · Console, and an unset (or stale) ID resolves to it rather
// than to nothing.
//
// The ID is named here rather than read from DefaultLayout, because a test
// that asks the registry what the default is agrees with the registry however
// the registry changes — which is the one thing this is here to catch.
func TestDefaultLayoutIsTheChosenArrangement(t *testing.T) {
	if got := DefaultLayout().ID; got != "console" {
		t.Errorf("DefaultLayout = %q, want the chosen arrangement", got)
	}
	if Layouts()[0].ID != DefaultLayout().ID {
		t.Error("the default is not first in the picker, so the list does not lead with what an operator gets")
	}
	unset := layoutModel("", 120, 34).View().Content
	stale := layoutModel("a-layout-from-a-later-build", 120, 34).View().Content
	chosen := layoutModel("console", 120, 34).View().Content
	if unset != chosen {
		t.Error("an unset layout does not render as the default one")
	}
	if stale != chosen {
		t.Error("a stale saved layout does not fall back to the default one")
	}
}

// The IDs go into a saved preference file and a --layout value, so they have
// to stay slug-shaped and distinct; the picker is being used to decide, so an
// option with no note is not a choice.
func TestLayoutIDsAreUniqueSlugsWithNotes(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range Layouts() {
		for _, r := range l.ID {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				t.Errorf("layout ID %q is not a plain slug", l.ID)
				break
			}
		}
		if seen[l.ID] {
			t.Errorf("duplicate layout ID %q", l.ID)
		}
		seen[l.ID] = true
		if l.Name == "" || l.Note == "" {
			t.Errorf("layout %q has an empty name or note", l.ID)
		}
	}
}

// An entry in the picker that draws the same screen as the one before it is
// a dead entry: the operator selects it, nothing moves, and the arrangement
// gets judged on the one they were already looking at.
func TestEveryLayoutChangesTheScreen(t *testing.T) {
	shipped := layoutModel(DefaultLayout().ID, 120, 34).View().Content
	for _, l := range Layouts() {
		if l.ID == DefaultLayout().ID {
			continue
		}
		if layoutModel(l.ID, 120, 34).View().Content == shipped {
			t.Errorf("layout %q renders identically to the shipped arrangement, so choosing it does nothing", l.ID)
		}
	}
}

// The frame invariant, for all six. A line wider than the terminal does not
// merely look wrong in alt-screen mode: it wraps, pushing every row below it
// down and off the bottom of the frame. The column layouts are the ones most
// able to break it, because a cell that overruns takes every column to its
// right with it.
func TestEveryLayoutFitsTheTerminal(t *testing.T) {
	for _, l := range Layouts() {
		for _, w := range []int{200, 140, 120, 100, 96, 80, 72, 60, 50, 44} {
			for _, h := range []int{40, 34, 24, 20, 14, 10} {
				m := layoutModel(l.ID, w, h)
				m.delta = model.Delta{Resolved: m.report.Findings[:1], New: m.report.Findings[1:3]}
				content := m.View().Content
				for _, line := range strings.Split(content, "\n") {
					if got := visibleWidth(line); got > w {
						t.Fatalf("%s at %dx%d: line is %d columns:\n  %q", l.ID, w, h, got, line)
					}
				}
				if got := strings.Count(content, "\n") + 1; got != h {
					t.Fatalf("%s at %dx%d: frame is %d lines", l.ID, w, h, got)
				}
			}
		}
	}
}

// The same, for the empty list and for the unscannable host. Both are
// separate code paths through the body, and the verdict band's headline is
// one of the two places on the screen big enough to be read as the answer.
func TestEveryLayoutFitsWithNothingToShow(t *testing.T) {
	for _, l := range Layouts() {
		for _, r := range []model.Report{
			{Domains: []model.DomainResult{{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy is not installed"}}},
			{},
		} {
			for _, w := range []int{120, 80, 44} {
				m := &appModel{mode: modeList, width: w, height: 24, report: r, selected: map[string]bool{}, layout: l.ID}
				m.active = m.report.Select(m.filter)
				content := m.View().Content
				for _, line := range strings.Split(content, "\n") {
					if got := visibleWidth(line); got > w {
						t.Errorf("%s at width %d: line is %d columns:\n  %q", l.ID, w, got, line)
					}
				}
				if got := strings.Count(content, "\n") + 1; got != 24 {
					t.Errorf("%s at width %d: frame is %d lines", l.ID, w, got)
				}
			}
		}
	}
}

// The list is the work; the rail and the pane are context. So when the
// terminal cannot hold all three, the context goes — and it goes in that
// order, the pane first — rather than the list being squeezed to a column
// where a finding's title no longer fits.
func TestColumnsAreGivenUpBeforeTheList(t *testing.T) {
	for _, l := range []string{"split", "console", "lanes", "railverdict"} {
		for _, w := range []int{200, 120, 100, 96, 80, 72, 60, 44} {
			m := layoutModel(l, w, 34)
			rail, list, pane := m.bodyColumns()
			if list < minListWidth && (rail > 0 || pane > 0) {
				t.Errorf("%s at %d: list squeezed to %d columns while rail=%d pane=%d",
					l, w, list, rail, pane)
			}
			// Counted in columns, not in separators: a separator is two
			// columns wide on a terminal that draws ambiguous characters wide,
			// and the arithmetic here has to be the arithmetic the renderer
			// uses or one of them is laying out a different screen.
			sep := 0
			for _, c := range []int{rail, pane} {
				if c > 0 {
					sep += sepWidth()
				}
			}
			if rail+list+pane+sep != w {
				t.Errorf("%s at %d: columns %d+%d+%d plus %d separator columns do not fill the width",
					l, w, rail, list, pane, sep)
			}
		}
	}
}

// A pane wide enough to matter, on a terminal wide enough for one, or there
// is no arrangement to judge. This is the assertion the width test cannot
// make: everything fits trivially if nothing is drawn.
func TestTheWidePaneAndRailAreActuallyDrawn(t *testing.T) {
	for _, tc := range []struct {
		id                 string
		wantRail, wantPane bool
	}{
		{"split", false, true},
		{"triage", false, false},
		{"console", true, true},
		{"railverdict", true, false},
		{"lanes", false, true},
		{"inline", false, false},
	} {
		rail, _, pane := layoutModel(tc.id, 140, 34).bodyColumns()
		if (rail > 0) != tc.wantRail {
			t.Errorf("%s: rail=%d, wanted drawn=%v", tc.id, rail, tc.wantRail)
		}
		if (pane > 0) != tc.wantPane {
			t.Errorf("%s: pane=%d, wanted drawn=%v", tc.id, pane, tc.wantPane)
		}
	}
}

// The rail's whole bet is that it explains a gap rather than marking one.
// The axes strip already says "N/A"; if the rail says only that, it has
// bought nothing with the twenty-four columns it took.
// The budgets are the point. The rail goes dense — a second row per domain —
// only when it has better than two rows each, and with twelve domains that
// needs 25 rows the body of a 30-row terminal does not have. So this asserted
// a property no real screen had: it passed at 40 rows and the reason was the
// first thing dropped at 20, in the one arrangement whose whole claim is that
// it carries the reason. Both budgets are checked now, and the tight one is
// the one that matters.
func TestRailNamesTheReasonADomainDidNotRun(t *testing.T) {
	for _, budget := range []int{40, 20, 16} {
		got := plain(strings.Join(layoutModel("console", 140, budget+10).railRows(railWidth, budget), "\n"))
		if !strings.Contains(got, "Trivy") {
			t.Errorf("budget=%d: the rail does not say why the CVE domain did not run:\n%s", budget, got)
		}
		if !strings.Contains(got, "N/A") {
			t.Errorf("budget=%d: the rail does not mark the skipped domain at all:\n%s", budget, got)
		}
		if n := len(layoutModel("console", 140, budget+10).railRows(railWidth, budget)); n > budget {
			t.Errorf("budget=%d: the rail drew %d rows", budget, n)
		}
	}
}

// The dashboard's rail is a sibling of everything else and runs the full
// height of the window, so the verdict band sits beside it rather than above
// it. The terminal drew the band across the whole width and started the rail
// under it, which is a different arrangement wearing the same name — and the
// shared registry exists precisely so "G" cannot mean two things.
func TestTheVerdictSitsBesideTheRailRatherThanAboveIt(t *testing.T) {
	m := layoutModel("railverdict", 140, 40)
	rows := m.listRows(30)
	if len(rows) == 0 {
		t.Fatal("no body rows")
	}
	first := plain(rows[0])
	if !strings.Contains(first, "DOMAINS") {
		t.Errorf("the rail does not start on the body's first row: %q", first)
	}
	joined := plain(strings.Join(rows, "\n"))
	if !strings.Contains(joined, "reachable right now") && !strings.Contains(joined, "This host is") {
		t.Errorf("the verdict is not drawn at all:\n%s", joined)
	}
	// The band is inside the list's column now, so its rows carry the rail's
	// separator ahead of them rather than starting at column zero.
	for i, r := range rows {
		if strings.Contains(plain(r), "unresolved ·") && !strings.HasPrefix(plain(r), " ") {
			t.Errorf("row %d puts the verdict outside the rail's column: %q", i, plain(r))
		}
	}
}

// A skipped domain must not be drawn with a full bar. It has no score, so
// whatever the zero value leaves in Score is not one — and rendered, that
// came out as a solid meter beside the letters "N/A", which is the exact
// confusion between "nothing there" and "I could not look" that every other
// layer of the scanner refuses to make.
func TestRailDrawsNoBarForADomainThatDidNotRun(t *testing.T) {
	m := layoutModel("console", 140, 40)
	for i := range m.report.Score.Axes {
		// A score that would fill the bar if it were drawn at all.
		m.report.Score.Axes[i].Score = 100
		m.report.Score.Axes[i].Applicable = m.report.Score.Axes[i].Source != model.SourceCVE
	}
	for _, row := range m.railRows(railWidth, 40) {
		p := plain(row)
		if !strings.Contains(p, "N/A") {
			continue
		}
		if strings.Contains(p, "█") {
			t.Errorf("a domain that did not run is drawn with a filled bar: %q", p)
		}
	}
}

// The service qualifies the title, so a row with the service in full beside
// one letter of the title has it exactly backwards. This only became
// reachable when the list stopped being the width of the terminal: in a
// column the suffix fits where the title does not, and the row came out as
// "agent.auth-disabled O  (openclaw@root)".
func TestANarrowRowKeepsTheTitleRatherThanTheService(t *testing.T) {
	f := model.NewFinding("agent.auth-disabled", "OpenClaw gateway accepts requests with no authentication",
		model.SeverityHigh, model.SourceAgent, model.RemediationManual,
		model.WithService("openclaw@root"))
	m := layoutModel("console", 140, 40)
	for _, w := range []int{46, 50, 56, 64} {
		row := plain(m.findingRow(f, false, w))
		if !strings.Contains(row, "(openclaw@root)") {
			continue // the suffix was dropped, which is the outcome under test
		}
		i := strings.Index(row, "(openclaw@root)")
		title := strings.TrimSpace(row[strings.Index(row, "agent.auth-disabled")+len("agent.auth-disabled") : i])
		if len([]rune(title)) < 16 {
			t.Errorf("width %d: kept the service and left %q of the title:\n  %q", w, title, row)
		}
	}
}

// A "HIGH · 0" heading is a row of screen spent announcing that nothing
// happened, and one per level on a nearly-clean host is the whole list.
func TestLanesOnlyHeadsSeveritiesThatArePresent(t *testing.T) {
	m := layoutModel("lanes", 120, 40)
	high := model.SeverityHigh
	m.filter.MinSeverity = &high
	m.active = m.report.Select(m.filter)

	rows, _ := m.laneRows(80)
	got := plain(strings.Join(rows, "\n"))
	if !strings.Contains(got, "HIGH") {
		t.Errorf("no lane for the severity that is present:\n%s", got)
	}
	for _, absent := range []string{"MED", "LOW"} {
		if strings.Contains(got, absent) {
			t.Errorf("a %s lane was drawn for a severity with nothing in it:\n%s", absent, got)
		}
	}
}

// The lane header offers an action, so the action has to exist and has to be
// the one it names: the cursor's severity, its auto-fixable findings, and
// nothing else. `a` is still what applies them — this only marks.
func TestMarkLaneMarksItsOwnSeverityAndOnlyTheAutos(t *testing.T) {
	m := layoutModel("lanes", 120, 40)
	// Onto a High, which is the severity carrying the Auto findings.
	for i, f := range m.active {
		if f.Severity == model.SeverityHigh {
			m.cursor = i
			break
		}
	}
	m.markLane()

	if len(m.selected) == 0 {
		t.Fatal("marking the lane marked nothing")
	}
	for _, f := range m.active {
		marked := m.selected[f.Key()]
		want := f.Severity == model.SeverityHigh && f.Remediation == model.RemediationAuto
		if marked != want {
			t.Errorf("%s/%s/%v: marked=%v, want %v", f.ID, f.Severity, f.Remediation, marked, want)
		}
	}
}

// The inline block opens under the row it belongs to, and comes out of the
// list's own rows rather than being added under them — so the footer does
// not move and the list is still a list around it.
func TestInlineOpensUnderTheCursorAndKeepsTheListAround(t *testing.T) {
	m := layoutModel("inline", 100, 34)
	m.cursor = 2
	rows := m.listColumn(20, 100)
	joined := plain(strings.Join(rows, "\n"))

	if !strings.Contains(joined, "How to fix") && !strings.Contains(joined, "HOW TO FIX") {
		t.Errorf("the cursor's finding did not open in place:\n%s", joined)
	}
	if len(rows) > 20 {
		t.Errorf("the inline block overran the budget: %d rows for 20", len(rows))
	}
	// The block must sit directly under the cursor's row and before the next
	// finding: an inline detail that is not inline is a pane drawn in the
	// wrong place. The cursor's own row is matched on its ID rather than its
	// service, because the selected row is padded and drops the suffix.
	blockRow := -1
	for i, r := range rows {
		if strings.HasPrefix(plain(r), "  │ ") {
			blockRow = i
			break
		}
	}
	if blockRow < 1 || !strings.Contains(plain(rows[blockRow-1]), "compose.ds018") {
		t.Errorf("the block opened at row %d, not under a finding row:\n%s", blockRow, joined)
	}
	if n := strings.Count(plain(rows[blockRow-1]), "svc-"); n != 0 {
		t.Errorf("row %d is not the selected row", blockRow-1)
	}
}

// "Nothing reachable" and "nobody looked" are opposite readings, and the verdict
// band is the largest text on the screen in the two arrangements that carry
// it. It is the one place a false all-clear would be read first and hardest.
func TestVerdictRefusesAVerdictWhenNothingCouldBeScanned(t *testing.T) {
	m := &appModel{mode: modeList, width: 120, height: 30, layout: "triage", selected: map[string]bool{},
		report: model.Report{Domains: []model.DomainResult{
			{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy is not installed"}}}}
	m.active = m.report.Select(m.filter)

	got := plain(strings.Join(m.verdictRows(120), "\n"))
	if !strings.Contains(got, "could not be scanned") {
		t.Errorf("the verdict did not refuse a reading of an unscanned host:\n%s", got)
	}
	for _, lie := range []string{"in good shape", "wide open", "exposed", "middling"} {
		if strings.Contains(got, lie) {
			t.Errorf("the verdict gave a band (%q) for a host nobody could look at:\n%s", lie, got)
		}
	}
}

// The verdict leads with what is reachable now when anything is, because
// that is the sentence the arrangement exists to put at the top.
func TestVerdictLeadsWithWhatIsReachableNow(t *testing.T) {
	got := plain(strings.Join(layoutModel("triage", 120, 30).verdictRows(120), "\n"))
	if !strings.Contains(got, "3 findings are reachable right now") {
		t.Errorf("the verdict does not lead with the exposed count:\n%s", got)
	}
	if !strings.Contains(got, "fix 10 safe findings") {
		t.Errorf("the verdict does not offer the batch fix:\n%s", got)
	}
}

// The spark strip's whole purpose is to cost one row where the strip costs
// three or four. A strip that wrapped would spend exactly what it is here to
// save, so axes are dropped from the right and the drop is marked.
func TestSparkStripIsOneRowAndSaysWhatItDropped(t *testing.T) {
	m := layoutModel("triage", 60, 30)
	row := m.sparkAxesLine(60)
	if strings.Contains(row, "\n") {
		t.Errorf("the spark strip wrapped:\n%s", row)
	}
	if visibleWidth(row) > 60 {
		t.Errorf("the spark strip is %d columns of 60: %q", visibleWidth(row), plain(row))
	}
	if !strings.Contains(plain(row), "+") {
		t.Errorf("axes were dropped without saying so: %q", plain(row))
	}
	// Wide enough for all of them: nothing dropped, nothing marked.
	if wide := plain(m.sparkAxesLine(400)); strings.Contains(wide, "+") {
		t.Errorf("a full strip claims to have dropped something: %q", wide)
	}
}

// Cancelling restores the arrangement that was in use rather than leaving
// whatever the cursor last rested on, and only enter writes the preference —
// the same contract the theme picker has.
func TestLayoutPickerKeepsAndCancels(t *testing.T) {
	saved := ""
	start := DefaultLayout().ID
	m := layoutModel(start, 120, 34)
	m.saveLayout = func(id string) error { saved = id; return nil }

	m.openLayoutPicker()
	if m.mode != modeLayout || m.layoutCursor != 0 {
		t.Fatalf("picker opened in mode %v at cursor %d", m.mode, m.layoutCursor)
	}
	m.keyLayout("down")
	m.keyLayout("esc")
	if m.layoutID() != start || saved != "" {
		t.Errorf("cancel left layout %q and saved %q", m.layoutID(), saved)
	}

	m.openLayoutPicker()
	m.keyLayout("down")
	m.keyLayout("down")
	m.keyLayout("enter")
	if want := Layouts()[2].ID; m.layoutID() != want || saved != want {
		t.Errorf("enter left layout %q and saved %q, want %q", m.layoutID(), saved, want)
	}
	if m.mode != modeList {
		t.Errorf("enter left the picker in mode %v", m.mode)
	}
}

// The two scroll positions count different things — findings in five of the
// arrangements, rendered rows in lanes — so carrying either across a switch
// scrolls the new arrangement to somewhere nobody asked for.
func TestSwitchingLayoutsDropsTheScrollPosition(t *testing.T) {
	m := layoutModel("split", 120, 34)
	m.offset, m.rowOffset = 12, 19
	m.setLayout("lanes")
	if m.offset != 0 || m.rowOffset != 0 {
		t.Errorf("switching kept offset=%d rowOffset=%d", m.offset, m.rowOffset)
	}
}

// A key that does something has to be in the footer, because the footer is
// the only documentation these bindings have.
func TestTheFooterNamesTheKeysTheArrangementAdds(t *testing.T) {
	if !strings.Contains(listHint, "l layout") {
		t.Error("the list footer does not name the layout key")
	}
	if !strings.Contains(laneListHint, "m select lane") {
		t.Error("the lanes footer does not name the key its own headers advertise")
	}
	if got := plain(layoutModel("lanes", 120, 34).View().Content); !strings.Contains(got, "m select lane") {
		t.Errorf("the lanes arrangement does not render its own key hint:\n%s", got)
	}
	// The theme picker previews under the cursor and says so. This one does
	// not, and a footer that promised a preview would leave the reader
	// waiting for a screen that never changes.
	if strings.Contains(layoutHint, "preview") {
		t.Error("the layout picker's footer promises a preview it does not give")
	}
}

// The Nerd set is a set of Private Use codepoints, and the frame is built by
// counting columns. internal/glyph holds every symbol to one column, but
// that is a claim about the table; this is the claim about the screen — the
// same widths, heights and arrangements the plain set is held to, drawn from
// the other table.
//
// It matters most for the header: the brand is the first thing on the widest
// row, so a symbol that measured wrong there would push the gauge off the
// end of every frame hostveil draws.
func TestEveryLayoutFitsWithNerdGlyphs(t *testing.T) {
	for _, l := range Layouts() {
		for _, w := range []int{200, 120, 100, 80, 60, 44} {
			for _, h := range []int{40, 24, 14, 10} {
				m := layoutModel(l.ID, w, h)
				m.gl = glyph.Nerd
				m.delta = model.Delta{Resolved: m.report.Findings[:1], New: m.report.Findings[1:3]}
				content := m.View().Content
				for _, line := range strings.Split(content, "\n") {
					if got := visibleWidth(line); got > w {
						t.Fatalf("%s at %dx%d: line is %d columns:\n  %q", l.ID, w, h, got, line)
					}
				}
				if got := strings.Count(content, "\n") + 1; got != h {
					t.Fatalf("%s at %dx%d: frame is %d lines", l.ID, w, h, got)
				}
			}
		}
	}
}

// Choosing the Nerd set has to actually change the screen, and choosing
// nothing has to leave it exactly as it was. The second half is the one that
// protects everybody who never opts in: glyph.Plain is the zero value, so a
// model built without a set must render what hostveil always rendered.
func TestTheGlyphSetReachesTheScreen(t *testing.T) {
	plain := layoutModel("split", 120, 34)
	nerd := layoutModel("split", 120, 34)
	nerd.gl = glyph.Nerd
	// A delta, so the resolved tick is on screen: the brand is drawn on every
	// frame but the tick only when something moved, and a set that reached
	// the header and nothing else would pass on the header alone.
	for _, m := range []*appModel{plain, nerd} {
		m.delta = model.Delta{Resolved: m.report.Findings[:2]}
	}

	if plain.View().Content == nerd.View().Content {
		t.Error("the nerd set renders identically to plain, so --glyphs does nothing")
	}
	unset := layoutModel("split", 120, 34)
	if unset.gl != glyph.Plain {
		t.Fatal("the zero glyph set is not Plain")
	}
	// Every symbol the header and the coverage notices draw, in the set the
	// terminal was told to use — and none of the other set's.
	got := plain.View().Content
	for _, sym := range []glyph.Symbol{glyph.Brand, glyph.OK} {
		if !strings.Contains(got, glyph.Plain.Of(sym)) {
			t.Errorf("the plain screen is missing %q", glyph.Plain.Of(sym))
		}
		if strings.Contains(got, glyph.Nerd.Of(sym)) {
			t.Errorf("the plain screen drew the nerd symbol %q", glyph.Nerd.Of(sym))
		}
	}
}
