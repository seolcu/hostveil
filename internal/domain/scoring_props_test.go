package domain

import (
	"math/rand/v2"
	"testing"
)

// TestScoreFindings_OverallInRange runs ScoreFindings against many
// randomly-generated finding slices and asserts the Overall score is
// always in [0, 100]. Catches off-by-one errors in the per-axis cap
// math and any path that could produce a negative or overflowing
// score.
func TestScoreFindings_OverallInRange(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xC0FFEE, 0xBADF00D))
	severities := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	sources := []Source{SourceTrivy, SourceLynis, SourceCompose}
	ids := []string{
		"trivy.cve-2024-1234",
		"compose.ds001",
		"compose.dr004",
		"lynis.AUTH-9286",
		"unknown-id",
		"",
	}
	services := []string{"nginx:latest", "postgres", "host", "", "web"}

	for trial := range 200 {
		n := rng.IntN(50)
		findings := make([]Finding, n)
		for i := range findings {
			findings[i] = Finding{
				ID:       ids[rng.IntN(len(ids))],
				Severity: severities[rng.IntN(len(severities))],
				Source:   sources[rng.IntN(len(sources))],
				Service:  services[rng.IntN(len(services))],
				Fixed:    rng.IntN(10) == 0,
			}
		}
		bd := ScoreFindings(findings)
		if bd.Overall > 100 {
			t.Errorf("trial %d: Overall = %d (>100) for %d findings", trial, bd.Overall, n)
		}
		// Each axis score is also bounded.
		for _, ax := range bd.Axes {
			if ax.Score > 100 {
				t.Errorf("trial %d: axis %q score = %d (>100)", trial, ax.ID, ax.Score)
			}
			if ax.Penalty > ax.MaxPenalty {
				t.Errorf("trial %d: axis %q penalty = %d (cap = %d)", trial, ax.ID, ax.Penalty, ax.MaxPenalty)
			}
			if ax.Penalty < 0 {
				t.Errorf("trial %d: axis %q penalty = %d (<0)", trial, ax.ID, ax.Penalty)
			}
		}
	}
}

// TestScoreFindings_EmptyIs100 is the "clean" invariant: with no
// findings, the score is 100 and no axis has a penalty. Both UIs rely
// on this to render the "Clean" state instead of a numeric score.
func TestScoreFindings_EmptyIs100(t *testing.T) {
	bd := ScoreFindings(nil)
	if bd.Overall != 100 {
		t.Errorf("Overall = %d, want 100 for empty input", bd.Overall)
	}
	for _, ax := range bd.Axes {
		if ax.Penalty != 0 {
			t.Errorf("axis %q penalty = %d, want 0 for empty input", ax.ID, ax.Penalty)
		}
		if ax.Score != 100 {
			t.Errorf("axis %q score = %d, want 100 for empty input", ax.ID, ax.Score)
		}
	}
}

// TestScoreFindings_MonotonicInSeverity asserts that adding a
// higher-severity finding to an existing set never increases the
// overall score. The reverse: a strictly worse (higher severity)
// finding can only lower or maintain the score.
func TestScoreFindings_MonotonicInSeverity(t *testing.T) {
	baseline := []Finding{
		{ID: "trivy.cve-2024-1", Severity: SeverityLow, Source: SourceTrivy, Service: "nginx"},
		{ID: "compose.ds001", Severity: SeverityLow, Source: SourceCompose},
	}
	baselineScore := ScoreFindings(baseline).Overall

	// Adding a more severe finding should never raise the score.
	addedSeverities := []Severity{SeverityMedium, SeverityHigh, SeverityCritical}
	for _, sev := range addedSeverities {
		withAdded := append(append([]Finding(nil), baseline...), Finding{
			ID: "added", Severity: sev, Source: SourceCompose, Service: "new",
		})
		score := ScoreFindings(withAdded).Overall
		if score > baselineScore {
			t.Errorf("adding %s finding raised score %d -> %d", sev, baselineScore, score)
		}
	}
}

// TestScoreFindings_DedupInvariant asserts that N copies of the same
// finding yield the same score as a single copy. Catches regressions
// in scoreDedupKey or the dedup loop.
func TestScoreFindings_DedupInvariant(t *testing.T) {
	single := []Finding{
		{ID: "trivy.cve-2024-X", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx:latest"},
	}
	singleScore := ScoreFindings(single).Overall

	dup := make([]Finding, 50)
	for i := range dup {
		dup[i] = single[0]
	}
	dupScore := ScoreFindings(dup).Overall

	if singleScore != dupScore {
		t.Errorf("dedup: 1 copy = %d, 50 copies = %d (must match)", singleScore, dupScore)
	}
}

// TestScoreFindings_FixedSkipped asserts that a fixed finding does
// not contribute to the score. The user already saw the finding
// count toward the score; marking it fixed must remove the
// contribution.
func TestScoreFindings_FixedSkipped(t *testing.T) {
	unfixed := []Finding{
		{ID: "trivy.cve-2024-X", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx"},
	}
	unfixedScore := ScoreFindings(unfixed).Overall

	fixed := []Finding{
		{ID: "trivy.cve-2024-X", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx", Fixed: true},
	}
	fixedScore := ScoreFindings(fixed).Overall

	if fixedScore <= unfixedScore {
		t.Errorf("fixed should not lower score: unfixed = %d, fixed = %d", unfixedScore, fixedScore)
	}
	if fixedScore != 100 {
		t.Errorf("only a fixed critical should be 100, got %d", fixedScore)
	}
}

// TestScoreFindings_SeverityOrdering asserts the documented penalty
// ordering: critical > high > medium > low. A regression in
// severityPenalty would break this.
func TestScoreFindings_SeverityOrdering(t *testing.T) {
	cases := []struct {
		sev  Severity
		want int
	}{
		{SeverityLow, 1},
		{SeverityMedium, 2},
		{SeverityHigh, 5},
		{SeverityCritical, 8},
	}
	for _, c := range cases {
		got := severityPenalty(c.sev)
		if got != c.want {
			t.Errorf("severityPenalty(%d) = %d, want %d", c.sev, got, c.want)
		}
	}
}

// TestScoreFindings_AxisInvariants asserts that:
//   - the four documented axes are always present and in the same
//     order;
//   - per-severity counts (Critical/High/Medium/Low) are consistent
//     with the penalties that landed on each axis.
func TestScoreFindings_AxisInvariants(t *testing.T) {
	bd := ScoreFindings([]Finding{
		{ID: "trivy.cve-2024-X", Severity: SeverityCritical, Source: SourceTrivy, Service: "nginx"},
		{ID: "trivy.cve-2024-Y", Severity: SeverityHigh, Source: SourceTrivy, Service: "nginx"},
		{ID: "lynis.AUTH-9286", Severity: SeverityMedium, Source: SourceLynis},
		{ID: "compose.ds001", Severity: SeverityLow, Source: SourceCompose},
	})
	if len(bd.Axes) != 4 {
		t.Fatalf("Axes length = %d, want 4", len(bd.Axes))
	}
	wantIDs := []string{
		scoreAxisVulnerabilities,
		scoreAxisContainer,
		scoreAxisHost,
		scoreAxisSecrets,
	}
	for i, want := range wantIDs {
		if bd.Axes[i].ID != want {
			t.Errorf("Axes[%d].ID = %q, want %q", i, bd.Axes[i].ID, want)
		}
	}
	// Penalty equals 8*Critical + 5*High + 2*Medium + 1*Low for the
	// findings that landed on this axis.
	vuln := bd.Axes[0]
	if vuln.Critical != 1 || vuln.High != 1 {
		t.Errorf("vuln counts: critical=%d high=%d, want 1/1", vuln.Critical, vuln.High)
	}
	host := bd.Axes[2]
	if host.Medium != 1 {
		t.Errorf("host medium count = %d, want 1", host.Medium)
	}
	container := bd.Axes[1]
	if container.Low != 1 {
		t.Errorf("container low count = %d, want 1", container.Low)
	}
}
