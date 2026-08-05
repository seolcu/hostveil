package tui

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/model"
)

// summaryReport is a host with a mixed severity spread, some fixable
// findings, and three domains that did not fully cover their ground — the
// ordinary shape of a self-hosted box, and the one the list screen has to
// summarise.
func summaryReport() model.Report {
	var fs []model.Finding
	add := func(n int, id string, sev model.Severity, rem model.RemediationKind) {
		for i := 0; i < n; i++ {
			fs = append(fs, model.NewFinding(id, "Datastore exposed on all network interfaces",
				sev, model.SourceCompose, rem, model.WithService(fmt.Sprintf("svc-%d", i))))
		}
	}
	add(3, "compose.ds018", model.SeverityExposed, model.RemediationAuto)
	add(5, "compose.ds016", model.SeverityWeak, model.RemediationManual)
	add(7, "compose.ds012", model.SeverityWeak, model.RemediationAuto)
	add(11, "compose.ds022", model.SeverityHardening, model.RemediationManual)

	axes := []model.ScoreAxis{{ID: "compose", Label: "compose", Applicable: true, Score: 42}}
	return model.Report{
		Findings: fs,
		Score:    model.ScoreBreakdown{Overall: 42, Applicable: true, Axes: axes},
		Domains: []model.DomainResult{
			{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy not installed"},
			{Source: model.SourceDockerd, State: model.ScanDegraded, Reason: "cannot inspect the docker.service unit"},
			{Source: model.SourceCompose, State: model.ScanDone, FindingCount: len(fs)},
		},
	}
}

func summaryModel(w, h int) *appModel {
	m := &appModel{mode: modeList, width: w, height: h,
		report: summaryReport(), selected: map[string]bool{}}
	m.active = m.report.Select(m.filter)
	return m
}

func plain(s string) string { return ansiSeq.ReplaceAllString(s, "") }

// The chip row is the dashboard's filter bar: how much of this wall of
// findings is Critical, and how much of it hostveil can fix on its own.
// Before it, the TUI answered neither without scrolling and counting.
func TestChipRowCarriesTheSeveritySpreadAndFixableCount(t *testing.T) {
	m := summaryModel(120, 30)
	row := plain(m.chipRow(200))
	for _, want := range []string{"EXPO 3", "WEAK 12", "HRDN 11", "FIXABLE 10"} {
		if !strings.Contains(row, want) {
			t.Errorf("chip row does not carry %q: %q", want, row)
		}
	}
	if !strings.Contains(plain(m.View().Content), "EXPO 3") {
		t.Errorf("the chip row is not on the list screen:\n%s", m.View().Content)
	}
}

// A severity nothing is at gets no chip, exactly as in the dashboard. An
// "EXPO 0" is a row of screen spent saying nothing happened.
func TestChipRowOmitsAnEmptySeverity(t *testing.T) {
	m := summaryModel(120, 30)
	m.report.Findings = m.report.Findings[:3] // the exposed ones only
	m.active = m.report.Select(m.filter)
	row := plain(m.chipRow(200))
	if !strings.Contains(row, "EXPO 3") {
		t.Fatalf("chip row lost the severity that is present: %q", row)
	}
	for _, gone := range []string{"WEAK", "HRDN"} {
		if strings.Contains(row, gone) {
			t.Errorf("chip row shows %q with nothing at it: %q", gone, row)
		}
	}
}

// The counts describe the host, not the filter. Counts that shrank with the
// list would be answering a question the list already answers, and the
// number a narrowed list most needs beside it is what it was narrowed from.
func TestChipCountsDoNotMoveWithTheFilter(t *testing.T) {
	m := summaryModel(120, 30)
	before := plain(m.chipRow(200))

	exposed := model.SeverityExposed
	m.filter.MinSeverity = &exposed
	m.filter.FixableOnly = true
	m.active = m.report.Select(m.filter)
	if len(m.active) == len(m.report.Findings) {
		t.Fatal("the filter did not narrow anything, so this proves nothing")
	}

	after := plain(m.chipRow(200))
	for _, want := range []string{"EXPO 3", "WEAK 12", "HRDN 11", "FIXABLE 10"} {
		if !strings.Contains(after, want) {
			t.Errorf("filtering changed the count %q:\n before %q\n after  %q", want, before, after)
		}
	}
}

// An active chip is filled — ink on the chip's own colour — the way the
// dashboard's stylesheet fills one, and the way this view already draws the
// row under the cursor.
func TestActiveChipIsFilled(t *testing.T) {
	m := summaryModel(120, 30)
	off := m.chipRow(200)

	exposed := model.SeverityExposed
	m.filter.MinSeverity = &exposed
	m.filter.FixableOnly = true
	m.active = m.report.Select(m.filter)

	if on := m.chipRow(200); on == off {
		t.Errorf("the chips render identically filtered and unfiltered: %q", plain(off))
	}
}

// A chip row too wide for its column drops whole chips and says how many. It
// used to be clipped by the frame instead, which cut through one: in the
// arrangement that puts a rail and a detail pane either side of the list, the
// column is narrow enough that "FIXABLE 38" was drawn as "FIXABLE 3". A
// clipped word is visibly clipped; a clipped count is a different number, and
// this row is nothing but counts.
func TestTheChipRowDropsWholeChipsAndSaysHowMany(t *testing.T) {
	m := summaryModel(120, 30)
	full := plain(m.chipRow(200))
	if !strings.Contains(full, "FIXABLE") {
		t.Fatalf("the fixture does not produce a FIXABLE chip: %q", full)
	}

	for w := 12; w <= lipgloss.Width(m.chipRow(200)); w += 3 {
		row := m.chipRow(w)
		if got := lipgloss.Width(row); got > w {
			t.Errorf("w=%d: the row is %d columns wide", w, got)
		}
		// Every count that survived must be the number it was in the full row,
		// digits and all. A trailing "+N" is the marker, not a count.
		body, _, _ := strings.Cut(plain(row), "  +")
		for _, chip := range strings.Fields(strings.TrimSpace(body)) {
			if _, err := strconv.Atoi(chip); err != nil {
				continue
			}
			if !strings.Contains(full, chip) {
				t.Errorf("w=%d: %q holds %q, which is in no chip of %q", w, plain(row), chip, full)
			}
		}
	}
}

// The domain filter's chip is the only place the domain is named — the head
// line's "3/26" says the list is narrowed but not by what — so a column too
// narrow for every chip must still keep that one.
func TestANarrowChipRowKeepsTheActiveFilter(t *testing.T) {
	m := summaryModel(120, 30)
	m.filter.Source = model.SourceSSH
	m.active = m.report.Select(m.filter)
	for w := 16; w <= 60; w += 4 {
		if row := plain(m.chipRow(w)); !strings.Contains(row, "SSH") {
			t.Errorf("w=%d: the active domain chip was dropped: %q", w, row)
		}
	}
}

// The fill above is an attribute, so it is gone the moment the output is
// stripped of styling — a pipe, a log, a terminal with nothing to render it
// with. What the list is showing has to survive that, and the head line is
// where: it prints the narrowed count over the unnarrowed one. Without it a
// filtered list is indistinguishable from a host with that many findings,
// which is the one reading that would send someone away satisfied.
func TestANarrowedListSaysSoInPlainText(t *testing.T) {
	m := summaryModel(120, 30)
	if got := plain(strings.Join(m.listRows(20), "\n")); !strings.Contains(got, "FINDINGS · 26") ||
		strings.Contains(got, "/26") {
		t.Errorf("an unfiltered list does not simply count its findings:\n%s", got)
	}

	exposed := model.SeverityExposed
	m.filter.MinSeverity = &exposed
	m.active = m.report.Select(m.filter)
	if got := plain(strings.Join(m.listRows(20), "\n")); !strings.Contains(got, "FINDINGS · 3/26") {
		t.Errorf("a filtered list does not print shown/total:\n%s", got)
	}
}

// A severity threshold is a range. Every chip at or above it is describing
// rows that are on screen, so every one of them reads as active — showing
// EXPO dim on a list of nothing but exposed findings is the opposite of the
// truth.
func TestSeverityChipsAboveTheThresholdAreAllActive(t *testing.T) {
	m := summaryModel(120, 30)
	weak := model.SeverityWeak
	m.filter.MinSeverity = &weak
	m.active = m.report.Select(m.filter)

	// The counts are the fixture's, read off it rather than written out, so
	// this test says something about the threshold and nothing about how
	// many findings summaryReport happens to build.
	counts := map[model.Severity]int{}
	for _, f := range m.report.Findings {
		counts[f.Severity]++
	}

	s := m.sty()
	for _, tc := range []struct {
		sev  model.Severity
		want bool
	}{
		{model.SeverityExposed, true},
		{model.SeverityWeak, true}, {model.SeverityHardening, false},
	} {
		label := fmt.Sprintf("%s %d", sevAbbr(tc.sev), counts[tc.sev])
		want := m.chip(label, tc.want, s.severityColor(tc.sev))
		if !strings.Contains(m.chipRow(200), want) {
			t.Errorf("%s: chip is not rendered with on=%v", tc.sev, tc.want)
		}
	}
}

// The axes strip marks a domain that did not run, but a mark is not an
// answer: "N/A" does not distinguish a host with no Docker from a scan that
// ran as a user who cannot read the socket, and those want opposite next
// steps. The CLI has always printed the reason and the dashboard shows it
// above the fold; this view showed it nowhere.
func TestListScreenNamesWhyADomainDidNotFullyRun(t *testing.T) {
	body := plain(summaryModel(120, 30).View().Content)
	for _, want := range []string{
		"CVEs skipped: Trivy not installed",
		"Dockerd partial: cannot inspect the docker.service unit",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the list screen does not carry %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Compose") {
		t.Error("a domain that completed is listed as a coverage gap")
	}
}

// A host that could scan almost nothing produces a notice per domain, which
// is a header taller than the list it heads. The region is capped, and the
// cap says how much it is hiding rather than silently dropping it.
func TestCoverageNoticesAreCappedAndSayHowManyAreHidden(t *testing.T) {
	m := summaryModel(120, 40)
	var doms []model.DomainResult
	for _, src := range model.AllSources() {
		doms = append(doms, model.DomainResult{Source: src, State: model.ScanSkipped, Reason: "nothing to scan"})
	}
	m.report.Domains = doms

	rows := m.coverageRows()
	if len(rows) != maxCoverageRows {
		t.Fatalf("%d coverage rows for %d skipped domains, want the cap of %d",
			len(rows), len(doms), maxCoverageRows)
	}
	last := plain(rows[len(rows)-1])
	if want := fmt.Sprintf("%d more", len(doms)-(maxCoverageRows-1)); !strings.Contains(last, want) {
		t.Errorf("the capped row does not say %q: %q", want, last)
	}
}

// An errored domain outranks a degraded one, which outranks a skipped one.
// The cap and the frame both cut from the bottom, so the order is what
// decides whether what survives is the alarming notice or the routine one.
func TestCoverageNoticesRunMostSevereFirst(t *testing.T) {
	m := summaryModel(120, 40)
	m.report.Domains = []model.DomainResult{
		{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy not installed"},
		{Source: model.SourceSSH, State: model.ScanError, Reason: "sshd_config unreadable"},
		{Source: model.SourceDockerd, State: model.ScanDegraded, Reason: "unit not inspectable"},
	}
	rows := m.coverageRows()
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	for i, want := range []string{"failed", "partial", "skipped"} {
		if !strings.Contains(plain(rows[i]), want) {
			t.Errorf("row %d is not the %s notice: %q", i, want, plain(rows[i]))
		}
	}
}

// The notices vary with the host, not with the design: a laptop with Docker
// and Trivy has none and a bare container has four. They are given up before
// the axes strip they annotate, rather than taking the whole header down to
// the one-line tier with them.
//
// Height 12 is the band where this is a real choice: the header still fits
// without the notices (2 rows of it, plus the rule and footer, leaves the
// body its minimum) and does not fit with them.
func TestCoverageIsShedBeforeTheAxesStrip(t *testing.T) {
	m := summaryModel(100, 12)
	m.report.Domains = []model.DomainResult{
		{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy not installed"},
		{Source: model.SourceSystemd, State: model.ScanSkipped, Reason: "systemd did not answer"},
		{Source: model.SourceDockerd, State: model.ScanSkipped, Reason: "cannot reach the Docker daemon"},
	}
	body := plain(m.View().Content)
	if !strings.Contains(body, "compose") {
		t.Errorf("the axes strip was dropped before the coverage notices:\n%s", body)
	}
	if strings.Contains(body, "Trivy not installed") {
		t.Errorf("the notices were kept at the axes strip's expense:\n%s", body)
	}
}

// Whatever the header ends up carrying, the frame is exactly as tall as the
// terminal — the property every mode is held to, asserted here with the two
// regions that are new.
func TestFrameHeightHoldsWithCoverageAndChips(t *testing.T) {
	for _, w := range []int{120, 80, 60, 44} {
		for _, h := range []int{40, 30, 24, 20, 16, 12, 10, 8, 6} {
			m := summaryModel(w, h)
			m.delta = model.Delta{Resolved: m.report.Findings[:1]}
			content := m.View().Content
			if got := strings.Count(content, "\n") + 1; got != h {
				t.Errorf("%dx%d: frame is %d lines, want %d", w, h, got, h)
			}
			for _, line := range strings.Split(content, "\n") {
				if got := visibleWidth(line); got > w {
					t.Errorf("%dx%d: line is %d columns:\n  %q", w, h, got, line)
				}
			}
		}
	}
}

// A clean host still says "Clean." rather than "No findings match the
// filter." The chip row is drawn from the unfiltered report, so it is there
// whenever the host has findings at all — using it to detect a filter would
// have turned every empty filtered list into the wrong message, and every
// genuinely clean host into the other wrong one.
func TestEmptyListDistinguishesAFilterFromACleanHost(t *testing.T) {
	filtered := summaryModel(100, 24)
	exposed := model.SeverityExposed
	filtered.filter.MinSeverity = &exposed
	filtered.filter.Source = model.SourceSSH // nothing in this report is SSH
	filtered.active = filtered.report.Select(filtered.filter)
	if len(filtered.active) != 0 {
		t.Fatalf("the filter matched %d findings, so this proves nothing", len(filtered.active))
	}
	if body := plain(filtered.View().Content); !strings.Contains(body, "No findings match the filter") {
		t.Errorf("a filtered-to-empty list does not say so:\n%s", body)
	}

	clean := summaryModel(100, 24)
	clean.report.Findings = nil
	clean.report.Domains = []model.DomainResult{{Source: model.SourceCompose, State: model.ScanDone}}
	clean.active = nil
	if body := plain(clean.View().Content); !strings.Contains(body, "Clean") {
		t.Errorf("a clean host is not told it is clean:\n%s", body)
	}
}

// The dashboard has two rows over its findings list: the filter chips, then a
// bar of batch buttons. The terminal had only the first, and what a batch
// would do was documented in the footer among fourteen other keys — so the
// state the list was actually in (two findings marked, `a` about to apply
// exactly those) was the one thing the screen did not say.
func TestTheBatchBarSaysWhatTheBatchKeyWouldDo(t *testing.T) {
	m := summaryModel(120, 30)
	if got := plain(m.batchRow(120)); !strings.Contains(got, "fix all") {
		t.Errorf("with nothing marked the bar does not offer the whole batch: %q", got)
	}

	// Marking changes what `a` does, so it has to change what the bar says.
	var marked int
	for _, f := range m.active {
		if f.Remediation == model.RemediationAuto && marked < 2 {
			m.selected[f.Key()] = true
			marked++
		}
	}
	if marked != 2 {
		t.Fatalf("the fixture produced %d Auto findings to mark", marked)
	}
	got := plain(m.batchRow(120))
	if !strings.Contains(got, "2 marked") {
		t.Errorf("the bar does not name the marked count: %q", got)
	}
	if strings.Contains(got, "fix all") {
		t.Errorf("the bar still offers the whole batch while a subset is marked: %q", got)
	}
	if !strings.Contains(got, "esc") {
		t.Errorf("the bar does not say how to clear the marks: %q", got)
	}
	// And it has to reach the screen, not just exist.
	if !strings.Contains(plain(strings.Join(m.listRows(24), "\n")), "2 marked") {
		t.Error("the batch bar is not drawn on the list screen")
	}
}

// The dashboard closes its detail pane with Preview fix and Explain with AI.
// The terminal closed it with nothing, so the two keys that act on the thing
// the pane is showing lived only in the footer.
func TestThePaneNamesTheKeysThatActOnWhatItShows(t *testing.T) {
	m := summaryModel(140, 34)
	rows := plain(strings.Join(m.paneRows(48, 30), "\n"))
	if !strings.Contains(rows, "explain with AI") {
		t.Errorf("the pane does not offer the AI explanation:\n%s", rows)
	}
	// A fixable finding gets the fix line; a Manual one must not, because a
	// key that does nothing is worse than a key nobody was told about.
	fixable := -1
	manual := -1
	for i, f := range m.active {
		if f.IsFixable() && fixable < 0 {
			fixable = i
		}
		if !f.IsFixable() && manual < 0 {
			manual = i
		}
	}
	if fixable < 0 || manual < 0 {
		t.Fatal("the fixture has no fixable/manual pair to compare")
	}
	m.cursor = fixable
	if got := plain(strings.Join(m.paneRows(48, 30), "\n")); !strings.Contains(got, "preview and apply") {
		t.Errorf("a fixable finding's pane does not offer the fix:\n%s", got)
	}
	m.cursor = manual
	if got := plain(strings.Join(m.paneRows(48, 30), "\n")); strings.Contains(got, "preview and apply") {
		t.Errorf("a manual finding's pane offers a fix that does not exist:\n%s", got)
	}
}

// The service is set flush right the way the dashboard sets it, so a column of
// container names can be read down. It goes back to trailing the title only
// when the row is too narrow for the gap to be a column at all.
func TestTheServiceIsSetFlushRightWhenThereIsRoom(t *testing.T) {
	f := model.NewFinding("compose.ds018", "Datastore exposed", model.SeverityExposed,
		model.SourceCompose, model.RemediationAuto, model.WithService("redis"))
	m := summaryModel(140, 30)

	wide := plain(m.findingRow(f, false, 120))
	if !strings.HasSuffix(strings.TrimRight(wide, " "), "(redis)") {
		t.Errorf("the service is not at the end of the row: %q", wide)
	}
	if !strings.Contains(wide, "exposed   ") {
		t.Errorf("the service was not pushed right, it is still trailing the title: %q", wide)
	}
	// Narrow enough that a right-aligned name would sit one space from the
	// title: that is not a column, so it trails instead.
	narrow := plain(m.findingRow(f, false, 46))
	if strings.Contains(narrow, "exposed   ") {
		t.Errorf("a narrow row still spends columns on the gap: %q", narrow)
	}
}
