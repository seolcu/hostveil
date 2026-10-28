package web

import (
	"strings"
	"testing"
)

// The axes strip's three parts add up to more than the grid track it is laid
// into is allowed to be, so the row overflowed its own cell. The meter is the
// part that may give — a bar two pixels shorter says the same thing, a label
// cut by two loses a letter and a number cut by two is a different number.
func TestTheAxisMeterIsTheThingThatShrinks(t *testing.T) {
	css := readAsset(t, "assets/app.css")
	for _, want := range []string{
		".axis { display: flex; align-items: center; gap: 10px; min-width: 0; }",
		".axis .meter { width: 92px; height: 8px; flex: 0 1 92px; min-width: 32px; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("app.css no longer has %q, so the axes strip can overflow its own grid cell again", want)
		}
	}
}

// Firefox is told what colour the scrollbar is, not left to work it out.
//
// The ::-webkit- rules beside it are Chromium's and Firefox ignores every one,
// so it had only `color-scheme: dark` — which themes.css has set all along and
// which is *usually* enough. Usually is the problem: measured against a page
// carrying nothing but that declaration, a headless Firefox draws a pure white
// bar, with and without the webkit rules present, and goes dark the moment
// scrollbar-color is set. Every screenshot this project has taken of the
// dashboard had a white stripe down the middle of the findings column.
//
// Palette roles, never a hex — --line-2 is the hairline the thumb was already
// drawn in, and TestEveryCSSVariableIsDeclared holds both names to a palette
// that actually declares them.
func TestTheScrollbarIsColouredRatherThanInferred(t *testing.T) {
	css := readAsset(t, "assets/app.css")
	for _, want := range []string{
		"scrollbar-color: var(--line-2) var(--ink);",
		"::-webkit-scrollbar-corner { background: var(--ink); }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("app.css no longer declares %q, so the scrollbar is back to whatever the browser infers", want)
		}
	}
}

// Every control a keyboard reaches has Hostveil's own focus ring.
//
// Buttons and the two selects have had one since they were added; the
// checkboxes, the fix-alternative radios and the clickable finding rows had
// none, so a keyboard user got the UA's — on Chromium a white outer ring
// around a black inner one, half of which vanishes on a dark ground.
func TestEveryFocusableControlHasTheSameRing(t *testing.T) {
	css := readAsset(t, "assets/app.css")
	const ring = "outline: 2px solid var(--safe); outline-offset: 1px;"
	for _, sel := range []string{".pick:focus-visible", ".alts input:focus-visible", ".finding:focus-visible"} {
		i := strings.Index(css, sel)
		if i < 0 {
			t.Errorf("%s has no focus rule, so the browser draws its own", sel)
			continue
		}
		if rest := css[i:]; !strings.Contains(rest[:min(len(rest), 400)], ring) {
			t.Errorf("%s does not take the same ring the buttons do", sel)
		}
	}
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := assets.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
