package domain

import "testing"

func TestScoreFindings_AxisBreakdown(t *testing.T) {
	breakdown := ScoreFindings([]Finding{
		{ID: "trivy.cve-2024-1234", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx:latest"},
		{ID: "trivy.ds001", Severity: SeverityHigh, Source: SourceTrivy},
		{ID: "lynis.AUTH-9286", Severity: SeverityMedium, Source: SourceLynis},
		{ID: "trivy.dr004", Severity: SeverityHigh, Source: SourceTrivy},
	})

	if breakdown.Overall != 80 {
		t.Fatalf("Overall = %d, want 80", breakdown.Overall)
	}
	if breakdown.Grade != "B" {
		t.Fatalf("Grade = %q, want B", breakdown.Grade)
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
		{ID: "trivy.ds001", Severity: SeverityCritical, Source: SourceTrivy, Fixed: true},
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
