package model

import (
	"strings"
	"testing"
)

// The sparkline lives on the model because both interfaces draw the same
// picture from the same points. A bucketing rule written twice is the shape
// that has already gone wrong here twice — the severity palette before
// internal/ui/theme, the domain table before /model.js.

func point(score uint8, applicable bool) ScorePoint {
	return ScorePoint{Overall: score, Applicable: applicable}
}

// Scores bucket against the fixed 0-100 range, never against the series'
// own min and max. Auto-scaling would turn 71→73 into a dramatic climb and
// a week flat at 42 into a line indistinguishable from a week flat at 4 —
// a chart that lies about the only thing it is for.
func TestSparklineBucketsAgainstTheFullRange(t *testing.T) {
	// A flat series is flat, wherever it sits, and two flat series at
	// different scores use different glyphs.
	low := Sparkline([]ScorePoint{point(4, true), point(4, true), point(4, true)})
	high := Sparkline([]ScorePoint{point(42, true), point(42, true), point(42, true)})
	for name, got := range map[string]string{"low": low, "high": high} {
		if len([]rune(got)) != 3 {
			t.Errorf("%s: %d glyphs for 3 points", name, len([]rune(got)))
		}
		if r := []rune(got); r[0] != r[1] || r[1] != r[2] {
			t.Errorf("%s: a flat series is not flat: %q", name, got)
		}
	}
	if low == high {
		t.Errorf("4 and 42 render identically (%q) — the scale is relative, not absolute", low)
	}

	// A near-flat climb at the top must not look like a climb from nothing.
	small := Sparkline([]ScorePoint{point(71, true), point(73, true)})
	full := Sparkline([]ScorePoint{point(0, true), point(100, true)})
	if small == full {
		t.Errorf("71→73 renders like 0→100 (%q)", small)
	}
}

// 0 is the lowest bar and 100 the highest, with nothing overflowing.
func TestSparklineSpansTheWholeRamp(t *testing.T) {
	got := []rune(Sparkline([]ScorePoint{point(0, true), point(100, true)}))
	if got[0] != '▁' {
		t.Errorf("0 renders as %q, want the lowest bar", string(got[0]))
	}
	if got[1] != '█' {
		t.Errorf("100 renders as %q, want the highest bar", string(got[1]))
	}
	// Every score in range must produce exactly one glyph from the ramp.
	for v := 0; v <= 100; v++ {
		s := Sparkline([]ScorePoint{point(uint8(v), true)})
		if len([]rune(s)) != 1 {
			t.Fatalf("score %d produced %q", v, s)
		}
		if !strings.ContainsAny(s, "▁▂▃▄▅▆▇█") {
			t.Fatalf("score %d produced %q, which is not on the ramp", v, s)
		}
	}
}

// A scan nobody could score is a gap, not a bar. It is not a zero — the
// aggregate score already refuses to say so, and a chart must not say it
// either.
func TestSparklineDrawsAGapForAnUnscorableScan(t *testing.T) {
	got := Sparkline([]ScorePoint{point(80, true), point(0, false), point(80, true)})
	r := []rune(got)
	if len(r) != 3 {
		t.Fatalf("got %q, want 3 glyphs", got)
	}
	if r[1] == r[0] || strings.ContainsAny(string(r[1]), "▁▂▃▄▅▆▇█") {
		t.Errorf("an unscorable scan drew a bar (%q) — it must be a gap", got)
	}
	// And specifically not the lowest bar, which is what a naive
	// zero-valued point would produce.
	if lowest := Sparkline([]ScorePoint{point(0, true)}); string(r[1]) == lowest {
		t.Errorf("an unscorable scan renders as score 0 (%q)", got)
	}
}

func TestSparklineOfNothingIsNothing(t *testing.T) {
	if got := Sparkline(nil); got != "" {
		t.Errorf("Sparkline(nil) = %q", got)
	}
}
