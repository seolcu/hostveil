package model

import (
	"math"
	"testing"
)

// The three-arm rule the interfaces used to each carry, now asserted once.
//
// Nothing checked it before: the "~" on a degraded axis is what keeps a
// partial result from reading as a clean one, and it existed in five places
// with no test in any of them.
func TestAxisValueTextSaysWhichKindOfNumberItIs(t *testing.T) {
	cases := []struct {
		name string
		axis ScoreAxis
		want string
	}{
		{"did not run", ScoreAxis{Applicable: false, Score: 100}, "N/A"},
		{"partial", ScoreAxis{Applicable: true, Degraded: true, Score: 88}, "88~"},
		{"complete", ScoreAxis{Applicable: true, Score: 88}, "88"},
		// A skipped axis carries whatever Score the zero value left behind,
		// and drawing that number is the confusion the whole scanner refuses.
		{"skipped keeps its zero value to itself", ScoreAxis{Applicable: false}, "N/A"},
	}
	for _, tc := range cases {
		if got := tc.axis.ValueText(); got != tc.want {
			t.Errorf("%s: ValueText() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestAxisHeadroomHidesItselfWhenItWouldSayNothing(t *testing.T) {
	cases := []struct {
		name string
		axis ScoreAxis
		want uint8
		show bool
	}{
		{"room to improve", ScoreAxis{Applicable: true, Score: 40, AfterSafeFixes: 90}, 90, true},
		{"nothing fixable", ScoreAxis{Applicable: true, Score: 40, AfterSafeFixes: 40}, 0, false},
		{"did not run", ScoreAxis{Applicable: false, Score: 0, AfterSafeFixes: 90}, 0, false},
	}
	for _, tc := range cases {
		got, show := tc.axis.Headroom()
		if got != tc.want || show != tc.show {
			t.Errorf("%s: Headroom() = (%d, %v), want (%d, %v)", tc.name, got, show, tc.want, tc.show)
		}
	}
}

// The overall is the cap-weighted geometric mean of the axes: every axis at r
// scores 100·r, and one collapsed axis pulls the whole down further than the
// arithmetic mean it replaced did.
func TestOverallIsTheWeightedGeometricMean(t *testing.T) {
	if got := weightedGeometricMean(0, 85); got != 100 {
		t.Errorf("every axis whole: %d, want 100", got)
	}
	// Two axes, caps 5 and 5: one at 1, one at 0.25 → 100·√0.25 = 50.
	logSum := 5*math.Log(1) + 5*math.Log(0.25)
	if got := weightedGeometricMean(logSum, 10); got != 50 {
		t.Errorf("√(1·0.25): %d, want 50", got)
	}
	// The arithmetic mean of the same two axes is 62.5.
	if got := weightedGeometricMean(logSum, 10); got >= 62 {
		t.Errorf("a collapsed axis must weigh more than in the arithmetic mean: %d", got)
	}
}
