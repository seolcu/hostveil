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
	var compose, ssh ScoreAxis
	for _, ax := range sb.Axes {
		switch ax.Source {
		case SourceCompose:
			compose = ax
			if ax.Penalty <= 0 || ax.High != 1 {
				t.Errorf("container axis penalty=%d high=%d", ax.Penalty, ax.High)
			}
		case SourceSSH:
			ssh = ax
			if ax.Penalty <= 0 || ax.Critical != 1 {
				t.Errorf("ssh axis penalty=%d crit=%d", ax.Penalty, ax.Critical)
			}
		default:
			if ax.Penalty != 0 || ax.Score != 100 {
				t.Errorf("%s axis unexpectedly penalized: %d", ax.ID, ax.Penalty)
			}
		}
	}
	// Penalties are a share of each axis's own cap, so they are not
	// comparable across axes. Scores are: a Critical must cost more of its
	// axis than a High costs of its own.
	if ssh.Score >= compose.Score {
		t.Errorf("critical axis scored %d, high axis %d — critical must cost more", ssh.Score, compose.Score)
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
	ranAll := map[Source]ScanState{
		SourceCompose: ScanDone, SourceSSH: ScanDone, SourceFirewall: ScanDone,
		SourceUpdates: ScanDone, SourceCVE: ScanDone,
	}
	ranNoCVE := map[Source]ScanState{
		SourceCompose: ScanDone, SourceSSH: ScanDone, SourceFirewall: ScanDone,
		SourceUpdates: ScanDone, SourceCVE: ScanSkipped,
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

// A domain that ran but covered only part of its ground is scored — partial
// evidence beats none — but flagged, so a UI never presents an incomplete
// axis as a plain clean result.
func TestScoreFlagsDegradedAxis(t *testing.T) {
	states := map[Source]ScanState{SourceCompose: ScanDone, SourceCVE: ScanDegraded}
	axes := axesBySource(ScoreReport(nil, states))

	if cve := axes[SourceCVE]; !cve.Applicable || !cve.Degraded {
		t.Errorf("degraded CVE axis: applicable=%v degraded=%v, want true/true", cve.Applicable, cve.Degraded)
	}
	if compose := axes[SourceCompose]; compose.Degraded {
		t.Error("a domain that completed must not be flagged degraded")
	}
}

// Error and Skipped both mean "did not run", so both drop out of scoring
// rather than being handed a perfect 100.
func TestScoreExcludesErroredAxis(t *testing.T) {
	states := map[Source]ScanState{SourceCompose: ScanDone, SourceCVE: ScanError}
	if cve := axesBySource(ScoreReport(nil, states))[SourceCVE]; cve.Applicable {
		t.Error("an errored domain's axis must be N/A, not a perfect score")
	}
}

// A nil map keeps the "score a bare set of findings" convention: every axis
// applicable, nothing degraded.
func TestScoreNilStatesMeansEverythingRan(t *testing.T) {
	for _, ax := range ScoreReport(nil, nil).Axes {
		if !ax.Applicable || ax.Degraded {
			t.Errorf("axis %s: applicable=%v degraded=%v, want true/false", ax.ID, ax.Applicable, ax.Degraded)
		}
	}
}

func axesBySource(s ScoreBreakdown) map[Source]ScoreAxis {
	m := make(map[Source]ScoreAxis, len(s.Axes))
	for _, ax := range s.Axes {
		m[ax.Source] = ax
	}
	return m
}

// The regression this whole model exists for: summing severities meant two
// Criticals exhausted an axis and every finding after that was free. An
// axis pinned at 0 cannot tell a bad host from a catastrophic one.
func TestScoreDoesNotSaturateOnASecondCritical(t *testing.T) {
	one := ScoreReport([]Finding{
		NewFinding("cve.outdated-image", "a", SeverityCritical, SourceCVE, RemediationReview, WithService("a")),
	}, nil)
	two := ScoreReport([]Finding{
		NewFinding("cve.outdated-image", "a", SeverityCritical, SourceCVE, RemediationReview, WithService("a")),
		NewFinding("cve.outdated-image", "b", SeverityCritical, SourceCVE, RemediationReview, WithService("b")),
	}, nil)

	got := func(sb ScoreBreakdown) uint8 {
		for _, ax := range sb.Axes {
			if ax.Source == SourceCVE {
				return ax.Score
			}
		}
		t.Fatal("no cve axis")
		return 0
	}
	if got(two) == 0 {
		t.Error("two criticals must not zero an axis; that is the saturation bug")
	}
	if got(two) >= got(one) {
		t.Errorf("second critical did not cost anything: %d then %d", got(one), got(two))
	}
}

// Every finding must cost something, no matter how many precede it.
func TestScoreIsMonotonic(t *testing.T) {
	var findings []Finding
	prev := uint8(100)
	for i := range 12 {
		findings = append(findings, NewFinding("compose.ds001", "x", SeverityHigh,
			SourceCompose, RemediationManual, WithService(string(rune('a'+i)))))
		got := ScoreReport(findings, nil).Overall
		if got > prev {
			t.Fatalf("adding finding %d raised the score: %d → %d", i, prev, got)
		}
		prev = got
	}
	if prev == 0 {
		t.Error("12 High findings on one axis should still leave a nonzero overall")
	}
}

// A finding nobody can fix still counts — claiming otherwise would be its
// own lie — but must not cost as much as one the user could act on.
func TestScoreWeighsUnavailableLighter(t *testing.T) {
	actionable := ScoreReport([]Finding{
		NewFinding("cve.outdated-image", "a", SeverityCritical, SourceCVE, RemediationReview),
	}, nil).Overall
	unfixable := ScoreReport([]Finding{
		NewFinding("cve.unpatched-image", "a", SeverityCritical, SourceCVE, RemediationUnavailable),
	}, nil).Overall

	if unfixable <= actionable {
		t.Errorf("unavailable finding cost %d, actionable cost %d — unavailable must cost less",
			100-unfixable, 100-actionable)
	}
	if unfixable >= 100 {
		t.Error("an unavailable finding must still cost something; the risk is real")
	}
}

// The point of the change: a host doing everything right still carries
// vulnerabilities with no upstream patch, and must not be scored as if it
// had done nothing. Under the additive model this axis read 0.
func TestScoreRewardsAWellMaintainedHost(t *testing.T) {
	var findings []Finding
	for i := range 4 {
		findings = append(findings, NewFinding("cve.unpatched-image", "no patch yet",
			SeverityCritical, SourceCVE, RemediationUnavailable, WithService(string(rune('a'+i)))))
	}
	sb := ScoreReport(findings, nil)
	for _, ax := range sb.Axes {
		if ax.Source != SourceCVE {
			continue
		}
		if ax.Score < 40 {
			t.Errorf("cve axis = %d; a host with only unpatchable CVEs is not a neglected one", ax.Score)
		}
	}
}

// A small cap used to be its own bug: fileperms caps at 6, so one Critical
// (penalty 8) clamped past the cap and zeroed the axis outright.
func TestScoreSmallCapAxisIsNotZeroedByOneFinding(t *testing.T) {
	sb := ScoreReport([]Finding{
		NewFinding("fileperms.shadow", "world-readable", SeverityCritical, SourceFilePerms, RemediationManual),
	}, nil)
	for _, ax := range sb.Axes {
		if ax.Source == SourceFilePerms && ax.Score == 0 {
			t.Error("one finding zeroed the smallest axis; cap must be a weight, not a threshold")
		}
	}
}
