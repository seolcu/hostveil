package web

import (
	"strings"
	"testing"
)

// Two faults found by driving the dashboard rather than by reading it, both
// of which a Go test can pin because both are questions about *order* in a
// file — which is what made them invisible in the first place.

// The dashboard has one detail node and three placements for it: the pane, an
// overlay, and — in the inline arrangement — inside the findings list, under
// the row that opened it.
//
// That last one puts it in a subtree the renderer rebuilds. `replaceChildren`
// on the list deletes it, and from then on every `getElementById("detail")`
// returns null: opening a finding, previewing a fix and pressing History all
// threw "Cannot read properties of null" until the page was reloaded. The
// list is rebuilt on every filter, every fix and every rescan, so in practice
// the inline arrangement broke on the second thing an operator did.
//
// The guard is to move the node back to <main> before the rebuild, and what
// this test pins is that it happens *first*. A guard after the rebuild is a
// guard over a node that no longer exists.
func TestTheDetailNodeIsRescuedBeforeTheListIsRebuilt(t *testing.T) {
	js := readAsset(t, "assets/app.js")

	guard := strings.Index(js, "list.contains(det)")
	if guard < 0 {
		t.Fatal("nothing moves the detail node out of the findings list before it is rebuilt — " +
			"the inline arrangement deletes it and every later lookup returns null")
	}
	rebuild := strings.Index(js, "list.replaceChildren(")
	if rebuild < 0 {
		t.Fatal("no list.replaceChildren in app.js — the renderer moved and this test did not")
	}
	if guard > rebuild {
		t.Error("the detail node is rescued after the list is rebuilt, which is after it has been deleted")
	}
}

// The spark strip (triage, inline) divides the window between twelve domains.
// At a phone width that is twelve one-letter labels: the score survives and
// what it is a score *of* does not, and the strip overflowed the window on
// top of it. The fix is a narrow-screen override that lets the strip scroll.
//
// It has to come *after* the rules it overrides. Both carry the specificity
// of an attribute selector plus a class, so the cascade is decided on order
// alone — and written in the earlier phone-width block, where every other
// narrow-screen rule lives, it lost silently and the strip stayed crammed.
func TestTheSparkStripsPhoneOverrideComesAfterTheRulesItOverrides(t *testing.T) {
	css := readAsset(t, "assets/app.css")

	base := strings.Index(css, `:root[data-layout="triage"] .axis,`)
	if base < 0 {
		t.Fatal("the spark strip's rules are gone from app.css")
	}
	override := strings.Index(css, `:root[data-layout="triage"] .axis,
  :root[data-layout="inline"] .axis { flex: 0 0 auto;`)
	if override < 0 {
		t.Fatal("no phone-width override for the spark strip: twelve domains in 480px is twelve " +
			"one-letter labels, and the strip overflows the window")
	}
	if override < base {
		t.Error("the phone-width override is written before the rules it overrides, so it never applies")
	}
}

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

// Every control a keyboard reaches has hostveil's own focus ring.
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
