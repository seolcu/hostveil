package theme

import (
	"math"
	"strconv"
	"testing"
)

// relativeLuminance implements the WCAG 2.1 definition for an sRGB color.
func relativeLuminance(hex string) float64 {
	channel := func(i int) float64 {
		v, err := strconv.ParseUint(hex[i:i+2], 16, 8)
		if err != nil {
			return 0
		}
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(1) + 0.7152*channel(3) + 0.0722*channel(5)
}

func contrast(fg, bg string) float64 {
	a, b := relativeLuminance(fg), relativeLuminance(bg)
	if a < b {
		a, b = b, a
	}
	return (a + 0.05) / (b + 0.05)
}

// A theme may not make a finding harder to read than the default one does.
//
// Severity is the only thing color carries here, and it is drawn as small
// text — a 10px uppercase label in the dashboard, a four-column abbreviation
// in the TUI — so WCAG's 4.5:1 for normal text is the applicable bar, not the
// 3:1 large-text one. The floors below are not aspirational: Instrument, the
// palette hostveil shipped before any of this existed, already clears every
// one of them, so this test asks a new theme for nothing the design did not
// already demand of itself.
//
// Low is the one exception, at 3.5:1. It is deliberately the quietest color
// in the system — a Low finding that shouted would drown out a Critical one —
// and Instrument sets it at 4.11:1 against the page and 3.86:1 against a
// raised row. Anything below 3.5 stops being quiet and starts being
// unreadable; the first drafts of Nord and Tokyo Night sat at 2.4 and 2.8.
func TestEveryThemeMeetsTheContrastFloor(t *testing.T) {
	floors := map[string]float64{
		"bone": 4.5, "slate": 4.5,
		"crit": 4.5, "high": 4.5, "med": 4.5, "safe": 4.5,
		"low": 3.5,
	}
	for _, th := range All() {
		p := th.Palette
		roles := map[string]string{
			"bone": p.Bone, "slate": p.Slate,
			"crit": p.Crit, "high": p.High, "med": p.Med, "low": p.Low, "safe": p.Safe,
		}
		// Both grounds a finding is ever drawn on: the page and the raised
		// surface used by hovered/selected rows and the fix preview box.
		for _, bg := range []struct{ name, hex string }{{"ink", p.Ink}, {"ink-2", p.Ink2}} {
			for role, hex := range roles {
				if got := contrast(hex, bg.hex); got < floors[role] {
					t.Errorf("%s: %s (%s) on %s (%s) is %.2f:1, want at least %.1f:1",
						th.ID, role, hex, bg.name, bg.hex, got, floors[role])
				}
			}
		}
	}
}

// The chrome has to stay visible too: a hairline or a meter track that blends
// into the page turns the axes strip into floating numbers.
func TestChromeIsDistinguishable(t *testing.T) {
	for _, th := range All() {
		p := th.Palette
		// Line2 is not only a hairline — it is the ground the TUI's cursor row
		// and the dashboard's selected row are drawn on, with Bone on top. The
		// row under the cursor is the one the user is about to act on, so it
		// is the last place that can afford to be hard to read.
		if got := contrast(p.Bone, p.Line2); got < 4.5 {
			t.Errorf("%s: bone (%s) on the selection ground line-2 (%s) is %.2f:1, want at least 4.5:1",
				th.ID, p.Bone, p.Line2, got)
		}
		for _, c := range []struct{ name, hex string }{{"line", p.Line}, {"line-2", p.Line2}} {
			if got := contrast(c.hex, p.Ink); got < 1.15 {
				t.Errorf("%s: %s (%s) is invisible against ink (%.2f:1)", th.ID, c.name, c.hex, got)
			}
		}
		// The raised surfaces must differ from the page, or a hovered row and
		// the fix preview box have no edge at all.
		for _, c := range []struct{ name, hex string }{{"ink-2", p.Ink2}, {"ink-3", p.Ink3}} {
			if c.hex == p.Ink {
				t.Errorf("%s: %s is identical to ink, so raised surfaces do not read as raised", th.ID, c.name)
			}
		}
	}
}
