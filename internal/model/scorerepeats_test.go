package model

import "testing"

// The anchor the whole model is built on has not moved: one High finding
// still takes half of what an axis has left. Everything below is about the
// second one and after.
func TestOneHighStillCostsHalf(t *testing.T) {
	fs := []Finding{NewFinding("compose.ds018", "t", SeverityHigh, SourceCompose, RemediationAuto)}
	got := ScoreReport(fs, map[Source]ScanState{SourceCompose: ScanDone}).Axes
	for _, a := range got {
		if a.Source == SourceCompose && a.Score != 50 {
			t.Errorf("one High leaves the axis at %d, want 50", a.Score)
		}
	}
}

// The same mistake written four times is not four independent risks. A
// compose file where every service is missing one line is one line missing,
// and a self-hoster runs many services from one template — so the old
// arithmetic buried an axis for having more services rather than worse ones.
//
// Pinned as an ordering rather than an exact number, because the number is
// the harmonic series and rounding it into an integer score is not the claim.
func TestRepeatsOfOneFindingCostLessEachTime(t *testing.T) {
	axis := func(fs []Finding) int {
		for _, a := range ScoreReport(fs, map[Source]ScanState{SourceCompose: ScanDone}).Axes {
			if a.Source == SourceCompose {
				return int(a.Score)
			}
		}
		t.Fatal("no compose axis")
		return 0
	}
	one := axis([]Finding{med("compose.ds009", "a")})
	four := axis([]Finding{med("compose.ds009", "a"), med("compose.ds009", "b"),
		med("compose.ds009", "c"), med("compose.ds009", "d")})
	// Four distinct mistakes, one per service, cost more than one mistake
	// repeated four times — that is the whole point.
	distinct := axis([]Finding{med("compose.ds009", "a"), med("compose.ds006", "b"),
		med("compose.ds012", "c"), med("compose.ds022", "d")})

	if !(one > four) {
		t.Errorf("four repeats (%d) did not cost more than one (%d)", four, one)
	}
	if !(four > distinct) {
		t.Errorf("four repeats of one mistake (%d) cost as much as four different ones (%d)", four, distinct)
	}
	// And the old pathology must not return by another door: a pile of
	// repeats still has to hurt more than a couple.
	twenty := make([]Finding, 0, 20)
	for i := range 20 {
		twenty = append(twenty, med("compose.ds009", string(rune('a'+i))))
	}
	if axis(twenty) >= four {
		t.Errorf("twenty repeats (%d) did not cost more than four (%d)", axis(twenty), four)
	}
}

// The same ID on two axes is two different mistakes and must not damp each
// other — the counter is keyed by axis as well as by ID.
func TestRepeatsAreCountedPerAxis(t *testing.T) {
	fs := []Finding{
		NewFinding("x.same", "t", SeverityHigh, SourceCompose, RemediationAuto, WithService("a")),
		NewFinding("x.same", "t", SeverityHigh, SourceSSH, RemediationAuto, WithService("b")),
	}
	for _, a := range ScoreReport(fs, map[Source]ScanState{SourceCompose: ScanDone, SourceSSH: ScanDone}).Axes {
		if (a.Source == SourceCompose || a.Source == SourceSSH) && a.Score != 50 {
			t.Errorf("%s axis is %d, want 50 — the first of an ID on its own axis costs half", a.ID, a.Score)
		}
	}
}

func med(id, svc string) Finding {
	return NewFinding(id, "t", SeverityMedium, SourceCompose, RemediationManual, WithService(svc))
}

// The order findings arrive in must not change the score, which the damping
// puts at risk: one ID can carry two severities — a CVE roll-up is the worst
// level in *that* image — and whichever instance is seen first would pay full
// price. The heaviest pays it, whatever the order.
func TestOrderStillDoesNotChangeTheScore(t *testing.T) {
	high := NewFinding("cve.outdated-image", "t", SeverityHigh, SourceCVE, RemediationReview, WithService("a"))
	low := NewFinding("cve.outdated-image", "t", SeverityLow, SourceCVE, RemediationReview, WithService("b"))
	axis := func(fs []Finding) uint8 {
		for _, a := range ScoreReport(fs, map[Source]ScanState{SourceCVE: ScanDone}).Axes {
			if a.Source == SourceCVE {
				return a.Score
			}
		}
		t.Fatal("no cve axis")
		return 0
	}
	if a, b := axis([]Finding{high, low}), axis([]Finding{low, high}); a != b {
		t.Errorf("score depends on the order findings arrive in: %d vs %d", a, b)
	}
}
