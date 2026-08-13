package model

import "testing"

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
		{"room to improve", ScoreAxis{Applicable: true, Score: 40, AfterFixes: 90}, 90, true},
		{"nothing fixable", ScoreAxis{Applicable: true, Score: 40, AfterFixes: 40}, 0, false},
		{"did not run", ScoreAxis{Applicable: false, Score: 0, AfterFixes: 90}, 0, false},
	}
	for _, tc := range cases {
		got, show := tc.axis.Headroom()
		if got != tc.want || show != tc.show {
			t.Errorf("%s: Headroom() = (%d, %v), want (%d, %v)", tc.name, got, show, tc.want, tc.show)
		}
	}
}
