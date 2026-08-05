package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/seolcu/hostveil/internal/model"
)

func emptyList(t *testing.T, r model.Report) string {
	t.Helper()
	m := tea.Model(&appModel{mode: modeList})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: r})
	return m.(*appModel).View().Content
}

// "Clean" is a claim about the whole host, and finding nothing is not the
// same as being unable to look. The two score identically and mean opposite
// things, which is the rule the whole scanner is built on — a skipped domain
// is N/A rather than 100, a degraded one is scored with a flag.
//
// This view broke the rule at the last step. It said "No problems found.
// Clean." whenever the list was empty, so a host where the Docker socket was
// unreachable and every checker had failed was reported spotless. Only the
// CLI refused, because the predicate lived in the CLI's renderer.
func TestListDoesNotClaimCleanWhenDomainsDidNotRun(t *testing.T) {
	for name, state := range map[string]model.ScanState{
		"skipped": model.ScanSkipped,
		"errored": model.ScanError,
		// Degraded is the interesting one: it ran, and it is scored, so
		// the flag most likely to be read as "fine" is the one that most
		// needs to not be.
		"degraded": model.ScanDegraded,
	} {
		t.Run(name, func(t *testing.T) {
			view := emptyList(t, model.Report{
				Domains: []model.DomainResult{
					{Source: model.SourceCompose, State: model.ScanDone},
					{Source: model.SourceCVE, State: state, Reason: "trivy is not installed"},
				},
			})
			if strings.Contains(view, "Clean.") {
				t.Errorf("claimed a clean host with a %s domain:\n%s", name, view)
			}
			if !strings.Contains(view, "did not complete") {
				t.Errorf("incomplete scan not called out:\n%s", view)
			}
		})
	}
}

func TestListClaimsCleanWhenEveryDomainRan(t *testing.T) {
	view := emptyList(t, model.Report{
		Domains: []model.DomainResult{
			{Source: model.SourceCompose, State: model.ScanDone},
			{Source: model.SourceCVE, State: model.ScanDone},
		},
	})
	if !strings.Contains(view, "No problems found. Clean.") {
		t.Errorf("a complete scan with no findings should read as clean:\n%s", view)
	}
}

// A report with no domains at all is not a failed scan — it is a bare
// finding set, which is what every zero-value model in these tests is. The
// guard must not turn those into a warning.
func TestListWithNoDomainsStillReadsClean(t *testing.T) {
	view := emptyList(t, model.Report{})
	if !strings.Contains(view, "No problems found. Clean.") {
		t.Errorf("a report with no domains should still read as clean:\n%s", view)
	}
}

// The filter message wins over both: an empty list behind a narrow filter
// says nothing about the host either way.
func TestFilteredEmptyListStillNamesTheFilter(t *testing.T) {
	m := tea.Model(&appModel{mode: modeList})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: model.Report{
		Findings: []model.Finding{model.NewFinding(
			"ssh.rootlogin", "root login permitted", model.SeverityHardening,
			model.SourceSSH, model.RemediationAuto)},
		Domains: []model.DomainResult{{Source: model.SourceCVE, State: model.ScanError}},
	}})
	// Narrow to a domain with no findings in it.
	am := m.(*appModel)
	am.filter.Source = model.SourceCompose
	am.rebuildActive()

	view := am.View().Content
	if !strings.Contains(view, "No findings match the filter.") {
		t.Errorf("filtered empty list should name the filter:\n%s", view)
	}
	if strings.Contains(view, "did not complete") {
		t.Errorf("filter message must not be replaced by the scan-coverage warning:\n%s", view)
	}
}

// The incomplete-scan message is five times longer than the "Clean." it
// replaces, and listRows does no wrapping of its own. Unwrapped at 40
// columns it was clipped to "No problems found in the domains that" — the
// warning gone, and what survived reading as the clean result the whole
// guard exists to withhold. The preview pane learned the same lesson about
// its rollback warning; this is that lesson applied here.
func TestEmptyListMessagesSurviveNarrowTerminals(t *testing.T) {
	reports := map[string]model.Report{
		"clean":      {Domains: []model.DomainResult{{Source: model.SourceCVE, State: model.ScanDone}}},
		"incomplete": {Domains: []model.DomainResult{{Source: model.SourceCVE, State: model.ScanError}}},
	}
	for _, w := range []int{40, 60, 80, 120} {
		for name, r := range reports {
			m := tea.Model(&appModel{mode: modeList})
			m = send(m, tea.WindowSizeMsg{Width: w, Height: 24})
			m = send(m, scannedMsg{report: r})
			view := m.(*appModel).View().Content

			for i, line := range strings.Split(view, "\n") {
				if got := visibleWidth(line); got > w {
					t.Errorf("width %d, %s: line %d is %d columns:\n%q", w, name, i, got, line)
				}
			}
			// Clipping shows up as a missing tail, so assert the last word
			// rather than a prefix that survives being cut.
			want := "complete."
			if name == "clean" {
				want = "Clean."
			}
			if !strings.Contains(view, want) {
				t.Errorf("width %d, %s: message clipped before %q:\n%s", w, name, want, view)
			}
		}
	}
}
