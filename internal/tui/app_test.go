package tui

import (
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func testModel() *model {
	return &model{
		filter: filterState{
			severity:    "all",
			source:      "all",
			remediation: "all",
			sortBy:      "severity",
		},
		phase: "ready",
	}
}

func TestSortFindings_Severity(t *testing.T) {
	findings := []domain.Finding{
		{Severity: domain.SeverityLow, Title: "Z low"},
		{Severity: domain.SeverityCritical, Title: "A critical"},
		{Severity: domain.SeverityHigh, Title: "B high"},
		{Severity: domain.SeverityMedium, Title: "C medium"},
		{Severity: domain.SeverityCritical, Title: "D critical"},
	}
	sortFindings(findings, "severity")
	if findings[0].Title != "A critical" {
		t.Errorf("expected first to be 'A critical', got %q", findings[0].Title)
	}
	if findings[1].Title != "D critical" {
		t.Errorf("expected second to be 'D critical', got %q", findings[1].Title)
	}
	if findings[2].Title != "B high" {
		t.Errorf("expected third to be 'B high', got %q", findings[2].Title)
	}
	if findings[3].Title != "C medium" {
		t.Errorf("expected fourth to be 'C medium', got %q", findings[3].Title)
	}
	if findings[4].Title != "Z low" {
		t.Errorf("expected fifth to be 'Z low', got %q", findings[4].Title)
	}
}

func TestSortFindings_Source(t *testing.T) {
	findings := []domain.Finding{
		{Source: domain.SourceTrivy, Severity: domain.SeverityLow, Title: "trivy low"},
		{Source: domain.SourceLynis, Severity: domain.SeverityCritical, Title: "lynis crit"},
		{Source: domain.SourceTrivy, Severity: domain.SeverityHigh, Title: "trivy high"},
		{Source: domain.SourceLynis, Severity: domain.SeverityMedium, Title: "lynis med"},
	}
	sortFindings(findings, "source")
	// "lynis" < "trivy" alphabetically, so lynis first, then trivy
	if findings[0].Title != "lynis crit" {
		t.Errorf("expected first 'lynis crit', got %q", findings[0].Title)
	}
	if findings[1].Title != "lynis med" {
		t.Errorf("expected second 'lynis med', got %q", findings[1].Title)
	}
	if findings[2].Title != "trivy high" {
		t.Errorf("expected third 'trivy high', got %q", findings[2].Title)
	}
	if findings[3].Title != "trivy low" {
		t.Errorf("expected fourth 'trivy low', got %q", findings[3].Title)
	}
}

func TestSortFindings_Title(t *testing.T) {
	findings := []domain.Finding{
		{Title: "Z finding", Severity: domain.SeverityCritical},
		{Title: "A finding", Severity: domain.SeverityLow},
		{Title: "M finding", Severity: domain.SeverityHigh},
	}
	sortFindings(findings, "title")
	if findings[0].Title != "A finding" {
		t.Errorf("expected first 'A finding', got %q", findings[0].Title)
	}
	if findings[1].Title != "M finding" {
		t.Errorf("expected second 'M finding', got %q", findings[1].Title)
	}
	if findings[2].Title != "Z finding" {
		t.Errorf("expected third 'Z finding', got %q", findings[2].Title)
	}
}

func TestSortFindings_Remediation(t *testing.T) {
	findings := []domain.Finding{
		{Remediation: domain.RemediationManual, Severity: domain.SeverityLow, Title: "manual low"},
		{Remediation: domain.RemediationAuto, Severity: domain.SeverityCritical, Title: "auto crit"},
		{Remediation: domain.RemediationUnavailable, Severity: domain.SeverityHigh, Title: "unavail high"},
		{Remediation: domain.RemediationReview, Severity: domain.SeverityMedium, Title: "review med"},
	}
	sortFindings(findings, "remediation")
	// alphabetical by String(): auto, manual, review, unavailable
	if findings[0].Title != "auto crit" {
		t.Errorf("expected first 'auto crit', got %q", findings[0].Title)
	}
	if findings[1].Title != "manual low" {
		t.Errorf("expected second 'manual low', got %q", findings[1].Title)
	}
	if findings[2].Title != "review med" {
		t.Errorf("expected third 'review med', got %q", findings[2].Title)
	}
	if findings[3].Title != "unavail high" {
		t.Errorf("expected fourth 'unavail high', got %q", findings[3].Title)
	}
}

func TestFindingMatches_ID(t *testing.T) {
	f := domain.Finding{ID: "CVE-2024-1234"}
	if !findingMatches(f, "CVE-2024-1234") {
		t.Error("expected exact ID match")
	}
}

func TestFindingMatches_Title(t *testing.T) {
	f := domain.Finding{Title: "Open SSH configuration"}
	if !findingMatches(f, "SSH") {
		t.Error("expected partial title match")
	}
}

func TestFindingMatches_Description(t *testing.T) {
	f := domain.Finding{Description: "The server allows password authentication"}
	if !findingMatches(f, "password") {
		t.Error("expected description match")
	}
}

func TestFindingMatches_HowToFix(t *testing.T) {
	f := domain.Finding{HowToFix: "Disable password authentication in sshd_config"}
	if !findingMatches(f, "sshd") {
		t.Error("expected how-to-fix match")
	}
}

func TestFindingMatches_Service(t *testing.T) {
	f := domain.Finding{Service: "nginx"}
	if !findingMatches(f, "nginx") {
		t.Error("expected service match")
	}
}

func TestFindingMatches_Severity(t *testing.T) {
	f := domain.Finding{Severity: domain.SeverityHigh}
	if !findingMatches(f, "high") {
		t.Error("expected severity match")
	}
}

func TestFindingMatches_Source(t *testing.T) {
	f := domain.Finding{Source: domain.SourceLynis}
	if !findingMatches(f, "lynis") {
		t.Error("expected source match")
	}
}

func TestFindingMatches_Remediation(t *testing.T) {
	f := domain.Finding{Remediation: domain.RemediationAuto}
	if !findingMatches(f, "auto") {
		t.Error("expected remediation match")
	}
}

func TestFindingMatches_CaseInsensitive(t *testing.T) {
	f := domain.Finding{Title: "Open SSH Configuration"}
	if !findingMatches(f, "ssh") {
		t.Error("expected case-insensitive match")
	}
	if !findingMatches(f, "SSH") {
		t.Error("expected uppercase query match")
	}
	if !findingMatches(f, "Ssh") {
		t.Error("expected mixed case query match")
	}
}

func TestFindingMatches_NoMatch(t *testing.T) {
	f := domain.Finding{
		ID:          "CVE-2024-1234",
		Title:       "Some finding",
		Description: "Some description",
		HowToFix:    "Some fix",
		Service:     "nginx",
		Severity:    domain.SeverityMedium,
		Source:      domain.SourceTrivy,
		Remediation: domain.RemediationUnavailable,
	}
	if findingMatches(f, "nonexistent") {
		t.Error("expected no match for nonexistent query")
	}
}

func TestCycleSourceFilter(t *testing.T) {
	m := &model{filter: filterState{source: "all"}}
	m.cycleSourceFilter()
	if m.filter.source != "trivy" {
		t.Errorf("expected 'trivy', got %q", m.filter.source)
	}
	m.cycleSourceFilter()
	if m.filter.source != "lynis" {
		t.Errorf("expected 'lynis', got %q", m.filter.source)
	}
	m.cycleSourceFilter()
	if m.filter.source != "all" {
		t.Errorf("expected 'all', got %q", m.filter.source)
	}
}

func TestCycleSourceFilter_WrapsFromLynis(t *testing.T) {
	m := &model{filter: filterState{source: "lynis"}}
	m.cycleSourceFilter()
	if m.filter.source != "all" {
		t.Errorf("expected 'all', got %q", m.filter.source)
	}
}

func TestCycleSortOrder(t *testing.T) {
	m := &model{filter: filterState{sortBy: "severity"}}
	m.cycleSortOrder()
	if m.filter.sortBy != "source" {
		t.Errorf("expected 'source', got %q", m.filter.sortBy)
	}
	m.cycleSortOrder()
	if m.filter.sortBy != "title" {
		t.Errorf("expected 'title', got %q", m.filter.sortBy)
	}
	m.cycleSortOrder()
	if m.filter.sortBy != "remediation" {
		t.Errorf("expected 'remediation', got %q", m.filter.sortBy)
	}
	m.cycleSortOrder()
	if m.filter.sortBy != "severity" {
		t.Errorf("expected 'severity', got %q", m.filter.sortBy)
	}
}

func TestShortID_Dotted(t *testing.T) {
	if got := shortID("lynis.AUTH-9286"); got != "AUTH-9286" {
		t.Errorf("expected 'AUTH-9286', got %q", got)
	}
}

func TestShortID_TrivyCVE(t *testing.T) {
	if got := shortID("trivy.CVE-2024-1234"); got != "CVE-2024-1234" {
		t.Errorf("expected 'CVE-2024-1234', got %q", got)
	}
}

func TestShortID_NoDot(t *testing.T) {
	got := shortID("short-id")
	if got != "short-id" {
		t.Errorf("expected 'short-id', got %q", got)
	}
}

func TestShortID_NoDotLong(t *testing.T) {
	got := shortID("abcdefghijklmnop")
	if got != "abcdefghijk…" {
		t.Errorf("expected 'abcdefghijk…', got %q", got)
	}
}

func TestShortID_Empty(t *testing.T) {
	if got := shortID(""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}
