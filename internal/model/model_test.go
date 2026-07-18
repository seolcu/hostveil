package model

import "testing"

// TestZeroValuesAreInert is the regression guard for the v2 footguns: the
// zero value of both RemediationKind and Source must be the invalid
// "unset" state, never a real, silently-valid default.
func TestZeroValuesAreInert(t *testing.T) {
	var rem RemediationKind
	if rem != RemediationUnset {
		t.Fatalf("zero RemediationKind = %v, want RemediationUnset", rem)
	}
	if rem.IsFixable() {
		t.Error("unset remediation must not be fixable")
	}
	if rem.Valid() {
		t.Error("unset remediation must not be valid")
	}

	var src Source
	if src != SourceUnset {
		t.Fatalf("zero Source = %v, want SourceUnset", src)
	}
	if src.Valid() {
		t.Error("unset source must not be valid")
	}
}

func TestRemediationFixability(t *testing.T) {
	fixable := map[RemediationKind]bool{
		RemediationUnset:       false,
		RemediationAuto:        true,
		RemediationReview:      true,
		RemediationManual:      false,
		RemediationUnavailable: false,
	}
	for kind, want := range fixable {
		if got := kind.IsFixable(); got != want {
			t.Errorf("%v.IsFixable() = %v, want %v", kind, got, want)
		}
	}
}

func TestFindingValidate(t *testing.T) {
	good := NewFinding("compose.ds016", "Docker socket mounted", SeverityCritical, SourceCompose, RemediationReview)
	if err := good.Validate(); err != nil {
		t.Errorf("well-formed finding failed validation: %v", err)
	}

	// A finding missing its remediation (built via struct literal, the v2
	// mistake) must be rejected.
	bad := Finding{ID: "x", Title: "t", Source: SourceCompose}
	if err := bad.Validate(); err == nil {
		t.Error("finding with unset remediation passed validation")
	}

	noSource := Finding{ID: "x", Title: "t", Remediation: RemediationAuto}
	if err := noSource.Validate(); err == nil {
		t.Error("finding with unset source passed validation")
	}
}

// TestAxisCapsSumTo100 guards the unenforced scoring invariant: when every
// axis runs, the overall score is a plain 100 − Σpenalty, which only holds
// if the axis caps sum to exactly 100. A future axis edit that breaks this
// silently distorts renormalization, so pin it here.
func TestAxisCapsSumTo100(t *testing.T) {
	sum := 0
	for _, def := range axisDefs {
		sum += def.cap
	}
	if sum != 100 {
		t.Errorf("axisDefs caps sum to %d, want 100", sum)
	}
}

// TestAllSourcesConsistent guards the source.go three-function contract:
// every real domain in AllSources must be Valid, must have a concrete (not
// "unset") String, and must own a scoring axis.
func TestAllSourcesConsistent(t *testing.T) {
	axisSources := make(map[Source]bool, len(axisDefs))
	for _, def := range axisDefs {
		axisSources[def.source] = true
	}
	for _, src := range AllSources() {
		if !src.Valid() {
			t.Errorf("AllSources contains invalid source %d", int(src))
		}
		if src.String() == "unset" {
			t.Errorf("source %d has no String() name", int(src))
		}
		if !axisSources[src] {
			t.Errorf("source %q (%d) has no scoring axis", src.String(), int(src))
		}
	}
	if got := len(AllSources()); got != len(axisDefs) {
		t.Errorf("AllSources has %d entries, axisDefs has %d", got, len(axisDefs))
	}
}

func TestScoreCleanHostIsPerfect(t *testing.T) {
	got := ScoreReport(nil, nil)
	if got.Overall != 100 {
		t.Errorf("clean host score = %d, want 100", got.Overall)
	}
	if len(got.Axes) != len(axisDefs) {
		t.Fatalf("got %d axes, want %d", len(got.Axes), len(axisDefs))
	}
}

func TestScorePenalizesCorrectAxis(t *testing.T) {
	findings := []Finding{
		NewFinding("compose.ds001", "privileged", SeverityHigh, SourceCompose, RemediationAuto),
		NewFinding("ssh.rootlogin", "root login", SeverityCritical, SourceSSH, RemediationReview),
	}
	sb := ScoreReport(findings, nil)
	for _, ax := range sb.Axes {
		switch ax.Source {
		case SourceCompose:
			if ax.Penalty != SeverityHigh.Penalty() || ax.High != 1 {
				t.Errorf("container axis penalty=%d high=%d", ax.Penalty, ax.High)
			}
		case SourceSSH:
			if ax.Penalty != SeverityCritical.Penalty() || ax.Critical != 1 {
				t.Errorf("ssh axis penalty=%d crit=%d", ax.Penalty, ax.Critical)
			}
		default:
			if ax.Penalty != 0 {
				t.Errorf("%s axis unexpectedly penalized: %d", ax.ID, ax.Penalty)
			}
		}
	}
	if sb.Overall >= 100 {
		t.Errorf("score should be reduced, got %d", sb.Overall)
	}
}

func TestScoreDeduplicates(t *testing.T) {
	f := NewFinding("compose.ds001", "privileged", SeverityHigh, SourceCompose, RemediationAuto, WithService("web"))
	one := ScoreReport([]Finding{f}, nil)
	two := ScoreReport([]Finding{f, f}, nil)
	if one.Overall != two.Overall {
		t.Errorf("duplicate finding changed score: %d vs %d", one.Overall, two.Overall)
	}
}

func TestScoreExcludesFixed(t *testing.T) {
	f := NewFinding("compose.ds001", "privileged", SeverityHigh, SourceCompose, RemediationAuto)
	f.Fixed = true
	if got := ScoreReport([]Finding{f}, nil).Overall; got != 100 {
		t.Errorf("fixed finding penalized score: %d", got)
	}
}

// TestScoreRenormalizesWhenCVESkipped verifies the N/A behavior: when the
// optional CVE domain does not run, its axis is N/A and the same set of
// non-CVE findings yields a *lower* score than when every axis counts,
// because the penalty is renormalized over a smaller cap sum.
func TestScoreRenormalizesWhenCVESkipped(t *testing.T) {
	findings := []Finding{
		NewFinding("compose.ds016", "docker socket", SeverityCritical, SourceCompose, RemediationReview),
	}
	ranAll := map[Source]bool{
		SourceCompose: true, SourceSSH: true, SourceFirewall: true,
		SourceUpdates: true, SourceCVE: true,
	}
	ranNoCVE := map[Source]bool{
		SourceCompose: true, SourceSSH: true, SourceFirewall: true,
		SourceUpdates: true, SourceCVE: false,
	}

	full := ScoreReport(findings, ranAll)
	skipped := ScoreReport(findings, ranNoCVE)

	for _, ax := range skipped.Axes {
		if ax.Source == SourceCVE && ax.Applicable {
			t.Error("CVE axis should be N/A when the domain did not run")
		}
	}
	if skipped.Overall >= full.Overall {
		t.Errorf("renormalized score %d should be below full-cap score %d", skipped.Overall, full.Overall)
	}
}
