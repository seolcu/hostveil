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
