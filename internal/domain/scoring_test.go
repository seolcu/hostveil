package domain

import "testing"

func TestScoreFindings_AxisBreakdown(t *testing.T) {
	breakdown := ScoreFindings([]Finding{
		{ID: "trivy.cve-2024-1234", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx:latest"},
		{ID: "compose.ds001", Severity: SeverityHigh, Source: SourceCompose},
		{ID: "lynis.AUTH-9286", Severity: SeverityMedium, Source: SourceLynis},
		{ID: "compose.dr004", Severity: SeverityHigh, Source: SourceCompose},
	})

	if breakdown.Overall != 80 {
		t.Fatalf("Overall = %d, want 80", breakdown.Overall)
	}

	byID := axesByID(breakdown.Axes)
	if byID[scoreAxisVulnerabilities].Penalty != 8 {
		t.Errorf("vulnerability penalty = %d, want 8", byID[scoreAxisVulnerabilities].Penalty)
	}
	if byID[scoreAxisContainer].Penalty != 5 {
		t.Errorf("container penalty = %d, want 5", byID[scoreAxisContainer].Penalty)
	}
	if byID[scoreAxisHost].Penalty != 2 {
		t.Errorf("host penalty = %d, want 2", byID[scoreAxisHost].Penalty)
	}
	if byID[scoreAxisSecrets].Penalty != 5 {
		t.Errorf("secrets penalty = %d, want 5", byID[scoreAxisSecrets].Penalty)
	}
}

// TestScoreFindings_GHSAOnlyTrivyFindingScoresAsVulnerability is a
// regression test: Trivy reports some vulnerabilities under a bare
// GHSA-style VulnerabilityID with no CVE ever assigned (common in
// npm/pip/gem ecosystem advisories). scoreAxisForFinding previously
// matched only the "trivy.cve-" prefix, so a "trivy.ghsa-..." finding
// was silently scored under Container exposure (the default branch)
// instead of Vulnerabilities -- wrong axis, wrong penalty cap (30 vs 35),
// and a misleading score breakdown shown to the user.
func TestScoreFindings_GHSAOnlyTrivyFindingScoresAsVulnerability(t *testing.T) {
	breakdown := ScoreFindings([]Finding{
		{ID: "trivy.ghsa-xqr8-7jwr-rhp7", Severity: SeverityCritical, Source: SourceTrivy, Service: "web"},
	})
	byID := axesByID(breakdown.Axes)
	if byID[scoreAxisVulnerabilities].Penalty != 8 {
		t.Errorf("vulnerability penalty = %d, want 8 (GHSA-only ID should score as a vulnerability)", byID[scoreAxisVulnerabilities].Penalty)
	}
	if byID[scoreAxisContainer].Penalty != 0 {
		t.Errorf("container penalty = %d, want 0 (GHSA-only ID must not fall through to Container exposure)", byID[scoreAxisContainer].Penalty)
	}
}

// TestScoreFindings_ZeroValueSourceDoesNotMisrouteToVulnerabilities is a
// regression test for a bug introduced while fixing the above: SourceTrivy
// is the zero value of the Source enum (iota starts at 0), so routing by
// `f.Source == SourceTrivy` (instead of by ID prefix) would incorrectly
// classify any finding that never had Source set at all as a
// vulnerability. A finding with no ID and no Source must fall through to
// the Container exposure default, matching pre-existing behavior.
func TestScoreFindings_ZeroValueSourceDoesNotMisrouteToVulnerabilities(t *testing.T) {
	breakdown := ScoreFindings([]Finding{
		{Severity: SeverityCritical},
	})
	byID := axesByID(breakdown.Axes)
	if byID[scoreAxisVulnerabilities].Penalty != 0 {
		t.Errorf("vulnerability penalty = %d, want 0 (zero-value Source must not be treated as Trivy)", byID[scoreAxisVulnerabilities].Penalty)
	}
	if byID[scoreAxisContainer].Penalty != 8 {
		t.Errorf("container penalty = %d, want 8 (zero-value Source/ID should fall through to Container exposure)", byID[scoreAxisContainer].Penalty)
	}
}

func TestScoreFindings_CapsVulnerabilityAxis(t *testing.T) {
	findings := make([]Finding, 10)
	for i := range findings {
		findings[i] = Finding{ID: "trivy.cve-2024-" + string(rune('a'+i)), Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx:latest"}
	}

	breakdown := ScoreFindings(findings)
	axis := axesByID(breakdown.Axes)[scoreAxisVulnerabilities]
	if axis.Penalty != 35 {
		t.Fatalf("vulnerability penalty = %d, want capped 35", axis.Penalty)
	}
	if breakdown.Overall != 65 {
		t.Fatalf("Overall = %d, want 65", breakdown.Overall)
	}
}

func TestScoreFindings_SkipsFixedAndDedupesByService(t *testing.T) {
	breakdown := ScoreFindings([]Finding{
		{ID: "trivy.cve-2024-1234", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx:latest"},
		{ID: "trivy.cve-2024-1234", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx:latest"},
		{ID: "trivy.cve-2024-1234", Severity: SeverityCritical, Source: SourceTrivy, Service: "postgres:latest"},
		{ID: "compose.ds001", Severity: SeverityCritical, Source: SourceCompose, Fixed: true},
	})

	byID := axesByID(breakdown.Axes)
	if byID[scoreAxisVulnerabilities].Penalty != 16 {
		t.Fatalf("vulnerability penalty = %d, want 16", byID[scoreAxisVulnerabilities].Penalty)
	}
	if byID[scoreAxisContainer].Penalty != 0 {
		t.Fatalf("container penalty = %d, want 0", byID[scoreAxisContainer].Penalty)
	}
}

func axesByID(axes []ScoreAxis) map[string]ScoreAxis {
	result := make(map[string]ScoreAxis, len(axes))
	for _, axis := range axes {
		result[axis.ID] = axis
	}
	return result
}
