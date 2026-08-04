package tui

import (
	"fmt"
	"strings"
	"testing"

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
	add(3, "compose.ds018", model.SeverityCritical, model.RemediationAuto)
	add(5, "compose.ds016", model.SeverityHigh, model.RemediationManual)
	add(7, "compose.ds012", model.SeverityMedium, model.RemediationAuto)
	add(11, "compose.ds022", model.SeverityLow, model.RemediationManual)

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
	row := plain(m.chipRow())
	for _, want := range []string{"CRIT 3", "HIGH 5", "MED 7", "LOW 11", "FIXABLE 10"} {
		if !strings.Contains(row, want) {
			t.Errorf("chip row does not carry %q: %q", want, row)
		}
	}
	if !strings.Contains(plain(m.View().Content), "CRIT 3") {
		t.Errorf("the chip row is not on the list screen:\n%s", m.View().Content)
	}
}

// A severity nothing is at gets no chip, exactly as in the dashboard. A
// "CRIT 0" is a row of screen spent saying nothing happened.
func TestChipRowOmitsAnEmptySeverity(t *testing.T) {
	m := summaryModel(120, 30)
	m.report.Findings = m.report.Findings[:3] // criticals only
	m.active = m.report.Select(m.filter)
	row := plain(m.chipRow())
	if !strings.Contains(row, "CRIT 3") {
		t.Fatalf("chip row lost the severity that is present: %q", row)
	}
	for _, gone := range []string{"HIGH", "MED", "LOW"} {
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
	before := plain(m.chipRow())

	crit := model.SeverityCritical
	m.filter.MinSeverity = &crit
	m.filter.FixableOnly = true
	m.active = m.report.Select(m.filter)
	if len(m.active) == len(m.report.Findings) {
		t.Fatal("the filter did not narrow anything, so this proves nothing")
	}

	after := plain(m.chipRow())
	for _, want := range []string{"CRIT 3", "HIGH 5", "MED 7", "LOW 11", "FIXABLE 10"} {
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
	off := m.chipRow()

	crit := model.SeverityCritical
	m.filter.MinSeverity = &crit
	m.filter.FixableOnly = true
	m.active = m.report.Select(m.filter)

	if on := m.chipRow(); on == off {
		t.Errorf("the chips render identically filtered and unfiltered: %q", plain(off))
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

	crit := model.SeverityCritical
	m.filter.MinSeverity = &crit
	m.active = m.report.Select(m.filter)
	if got := plain(strings.Join(m.listRows(20), "\n")); !strings.Contains(got, "FINDINGS · 3/26") {
		t.Errorf("a filtered list does not print shown/total:\n%s", got)
	}
}

// A severity threshold is a range. Every chip at or above it is describing
// rows that are on screen, so every one of them reads as active — showing
// CRIT dim on a list of nothing but Criticals is the opposite of the truth.
func TestSeverityChipsAboveTheThresholdAreAllActive(t *testing.T) {
	m := summaryModel(120, 30)
	med := model.SeverityMedium
	m.filter.MinSeverity = &med
	m.active = m.report.Select(m.filter)

	s := m.sty()
	for _, tc := range []struct {
		sev  model.Severity
		want bool
	}{
		{model.SeverityCritical, true}, {model.SeverityHigh, true},
		{model.SeverityMedium, true}, {model.SeverityLow, false},
	} {
		label := fmt.Sprintf("%s %d", sevAbbr(tc.sev), map[model.Severity]int{
			model.SeverityCritical: 3, model.SeverityHigh: 5,
			model.SeverityMedium: 7, model.SeverityLow: 11}[tc.sev])
		want := m.chip(label, tc.want, s.severityColor(tc.sev))
		if !strings.Contains(m.chipRow(), want) {
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
	crit := model.SeverityCritical
	filtered.filter.MinSeverity = &crit
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
