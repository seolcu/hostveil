package model

import "testing"

// The boundaries are the whole content of the type, and they were the one
// thing no test touched while four renderers each wrote them out by hand.
func TestBandBoundaries(t *testing.T) {
	for _, tc := range []struct {
		score uint8
		want  Band
	}{
		{0, BandCritical},
		{24, BandCritical},
		{25, BandPoor},
		{49, BandPoor},
		{50, BandFair},
		{79, BandFair},
		{80, BandGood},
		{100, BandGood},
	} {
		if got := BandFor(tc.score); got != tc.want {
			t.Errorf("BandFor(%d) = %v, want %v", tc.score, got, tc.want)
		}
	}
}

// BandFor must answer for every score a ScoreBreakdown can hold, and the
// answer must never improve as the score falls.
func TestBandIsTotalAndMonotonic(t *testing.T) {
	prev := BandFor(0)
	for v := 0; v <= 100; v++ {
		b := BandFor(uint8(v)) //nolint:gosec // bounded by the loop
		if b.String() == "" {
			t.Fatalf("BandFor(%d) has no name", v)
		}
		if b > prev {
			t.Fatalf("BandFor(%d) = %v is worse than BandFor(%d) = %v; bands must improve with the score",
				v, b, v-1, prev)
		}
		prev = b
	}
}

// Every band must be reachable, or a renderer builds an appearance for a
// class no host can ever be in.
func TestEveryBandIsReachable(t *testing.T) {
	seen := map[Band]bool{}
	for v := 0; v <= 100; v++ {
		seen[BandFor(uint8(v))] = true //nolint:gosec // bounded by the loop
	}
	for _, b := range Bands() {
		if !seen[b] {
			t.Errorf("band %v is never returned for any score", b)
		}
		if BandFor(b.Min()) != b {
			t.Errorf("band %v has Min %d, but BandFor(%d) = %v", b, b.Min(), b.Min(), BandFor(b.Min()))
		}
	}
	if len(seen) != len(Bands()) {
		t.Errorf("%d bands reachable, but Bands() lists %d", len(seen), len(Bands()))
	}
}

// Names are how the dashboard keys its band table, so two bands sharing one
// would silently collapse a range.
func TestBandNamesAreDistinct(t *testing.T) {
	seen := map[string]Band{}
	for _, b := range Bands() {
		if prev, dup := seen[b.String()]; dup {
			t.Errorf("bands %v and %v share the name %q", prev, b, b.String())
		}
		seen[b.String()] = b
	}
}
