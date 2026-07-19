package clirender

import (
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
