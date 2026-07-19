package clirender

import (
	"fmt"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func plain(r model.Report) string { return Text(r, Options{}) }

// A domain that ran but covered only part of its ground must appear. Before
// ScanDegraded had any renderer, such a domain printed nothing at all — the
// report looked exactly like a complete one.
func TestTextRendersDegradedDomain(t *testing.T) {
	out := plain(model.Report{
		Score: model.ScoreReport(nil, map[model.Source]model.ScanState{model.SourceCVE: model.ScanDegraded}),
		Domains: []model.DomainResult{{
			Source: model.SourceCVE,
			State:  model.ScanDegraded,
			Reason: "some images could not be scanned (covered 1 of 9)",
		}},
	})

	if !strings.Contains(out, "partial") {
		t.Errorf("degraded domain not rendered:\n%s", out)
	}
	if !strings.Contains(out, "covered 1 of 9") {
		t.Errorf("degraded reason not rendered:\n%s", out)
	}
}

// The axis carries the flag too: a bare "100" next to a partially-scanned
// domain reads as a clean result.
func TestTextMarksDegradedAxis(t *testing.T) {
	out := plain(model.Report{
		Score: model.ScoreReport(nil, map[model.Source]model.ScanState{
			model.SourceCVE: model.ScanDegraded, model.SourceCompose: model.ScanDone,
		}),
	})
	if !strings.Contains(out, "(partial)") {
		t.Errorf("degraded axis not marked:\n%s", out)
	}
	if strings.Count(out, "(partial)") != 1 {
		t.Errorf("only the degraded axis should be marked:\n%s", out)
	}
}

func TestTextRendersSkippedAndErroredDomains(t *testing.T) {
	out := plain(model.Report{
		Domains: []model.DomainResult{
			{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy not installed"},
			{Source: model.SourceCompose, State: model.ScanError, Reason: "list compose projects: permission denied"},
		},
	})
	if !strings.Contains(out, "skipped: Trivy not installed") {
		t.Errorf("skipped domain not rendered:\n%s", out)
	}
	if !strings.Contains(out, "error: list compose projects: permission denied") {
		t.Errorf("errored domain not rendered:\n%s", out)
	}
}

// "Clean" is a claim about the whole host. With domains missing, the most the
// report can honestly say is that what it looked at was clean.
func TestTextDoesNotClaimCleanWhenDomainsDidNotRun(t *testing.T) {
	out := plain(model.Report{
		Domains: []model.DomainResult{
			{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy not installed"},
		},
	})
	if strings.Contains(out, "Clean.") {
		t.Errorf("claimed a clean host despite a skipped domain:\n%s", out)
	}
	if !strings.Contains(out, "did not complete") {
		t.Errorf("incomplete scan not called out:\n%s", out)
	}
}

func TestTextClaimsCleanWhenEveryDomainRan(t *testing.T) {
	out := plain(model.Report{
		Domains: []model.DomainResult{
			{Source: model.SourceCVE, State: model.ScanDone},
			{Source: model.SourceCompose, State: model.ScanDone},
		},
	})
	if !strings.Contains(out, "Clean.") {
		t.Errorf("a complete scan with no findings should read as clean:\n%s", out)
	}
}

// A "short summary" that names every change is not short. Bringing up one
// new stack already produces hundreds of entries, and a release that changes
// how a domain represents its findings can retire thousands of keys at once.
func TestDeltaSummaryBoundsItsListing(t *testing.T) {
	var resolved []model.Finding
	for i := range 6400 {
		resolved = append(resolved, model.NewFinding(
			fmt.Sprintf("cve.cve-2024-%04d", i), "t", model.SeverityHigh,
			model.SourceCVE, model.RemediationManual))
	}

	out := DeltaSummary(model.Delta{Resolved: resolved})

	if n := strings.Count(out, "✓ resolved:"); n > 12 {
		t.Errorf("summary listed %d resolved lines; it must be bounded", n)
	}
	// The count that was truncated must be stated: a silent cut reads as
	// "that was all of them".
	if !strings.Contains(out, "and 6390 more") {
		t.Errorf("summary does not say how many it left out:\n%s", out)
	}
	// The true total still has to appear.
	if !strings.Contains(out, "6400 resolved") {
		t.Errorf("summary lost the real total:\n%s", out)
	}
}
