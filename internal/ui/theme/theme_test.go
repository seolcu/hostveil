package theme

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var hex = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// Every role of every palette must be set and well-formed. A missing role is
// not a cosmetic bug: an empty string reaches lipgloss as an invalid color and
// the TUI renders that text unstyled, so a whole severity can silently stop
// looking like a severity.
func TestPalettesComplete(t *testing.T) {
	for _, th := range All() {
		v := reflect.ValueOf(th.Palette)
		for i := 0; i < v.NumField(); i++ {
			role := v.Type().Field(i).Name
			got := v.Field(i).String()
			if !hex.MatchString(got) {
				t.Errorf("%s.%s = %q, want lowercase #rrggbb", th.ID, role, got)
			}
		}
	}
}

func TestRegistryShape(t *testing.T) {
	seen := map[string]bool{}
	for _, th := range All() {
		switch {
		case th.ID == "":
			t.Error("a theme has no ID")
		case th.ID != strings.ToLower(th.ID):
			t.Errorf("theme ID %q is not lowercase — it is typed on a command line", th.ID)
		case seen[th.ID]:
			t.Errorf("duplicate theme ID %q", th.ID)
		case th.Name == "":
			t.Errorf("theme %q has no display name", th.ID)
		}
		seen[th.ID] = true
	}
	if _, ok := Lookup(Default().ID); !ok {
		t.Errorf("Default() = %q, which is not in the registry", Default().ID)
	}
	if got, want := len(IDs()), len(All()); got != want {
		t.Errorf("IDs() has %d entries, All() has %d", got, want)
	}
}

// All returns a copy: a caller that mutates the slice it gets back must not
// be able to edit the registry out from under every other UI.
func TestAllIsACopy(t *testing.T) {
	got := All()
	got[0] = Theme{ID: "tampered"}
	if Default().ID == "tampered" {
		t.Error("All() handed out the registry's own backing array")
	}
}

// The default look must not shift under anyone. This is the table every
// screenshot, every doc and the brand mark are calibrated to, written out
// again so that changing it is a decision rather than a diff nobody read.
//
// Four of the twelve are not One Dark's published values. Three of those are
// not drift — TestEveryThemeMeetsTheContrastFloor rejects the published Slate,
// Crit and Low outright — and the fourth, Bone, is a judgement with its own
// reason beside it. Either way somebody comparing this against Atom will find
// a discrepancy and be right to ask, so the numbers are pinned here with the
// ones they replaced beside them.
func TestOneDarkUnchanged(t *testing.T) {
	want := Palette{
		Ink: "#282c34", Ink2: "#21252b", Ink3: "#2f343f",
		Line: "#181a1f", Line2: "#3e4451",
		Bone:  "#c8ccd4", // One Dark's fg #abb2bf, lifted for a denser view
		Slate: "#8e939b", // #7f848e was 3.73:1 on ink, floor is 4.5
		Crit:  "#e17079", // #e06c75 was 4.38:1 on ink
		High:  "#d19a66", Med: "#e5c07b",
		Low:  "#79808e", // #767d8c was 3.39:1 on ink, floor is 3.5
		Safe: "#98c379",
	}
	got, ok := Lookup("onedark")
	if !ok {
		t.Fatal("the onedark theme is gone")
	}
	if got.Palette != want {
		t.Errorf("onedark palette changed:\n got %+v\nwant %+v", got.Palette, want)
	}
	if Default().ID != "onedark" {
		t.Errorf("Default() = %q, want onedark", Default().ID)
	}
}

// The theme that used to be the default is gone, and nothing may quietly
// bring it back: its palette was tuned against a near-black page that no
// remaining theme has, so a stray "instrument" entry would be an
// unmaintained twelfth of the design system rather than a choice.
func TestInstrumentIsGone(t *testing.T) {
	if _, ok := Lookup("instrument"); ok {
		t.Error("the instrument theme is back in the registry")
	}
}

func TestCSSCoversEveryTheme(t *testing.T) {
	css := CSS("nord")
	if !strings.Contains(css, ":root {") {
		t.Error("CSS has no bare :root block, so the page has no palette before script runs")
	}
	// The bare :root block must carry the requested default, not the registry
	// default — that block is what paints the first frame.
	root := css[strings.Index(css, ":root {"):strings.Index(css, `:root[data-theme=`)]
	nord, _ := Lookup("nord")
	if !strings.Contains(root, nord.Palette.Ink) {
		t.Errorf(":root block does not use the requested default's ink %s:\n%s", nord.Palette.Ink, root)
	}

	for _, th := range All() {
		sel := `:root[data-theme="` + th.ID + `"]`
		if !strings.Contains(css, sel) {
			t.Errorf("CSS has no block for %q — the picker could not switch to it", th.ID)
		}
		v := th.Palette.vars()
		for name, val := range v {
			if !strings.Contains(css, name+": "+val+";") {
				t.Errorf("CSS is missing %s: %s (theme %s)", name, val, th.ID)
			}
		}
	}
}

// An unknown default must not produce a stylesheet with no :root palette at
// all; the page would render as unstyled black-on-white.
func TestCSSUnknownDefaultFallsBack(t *testing.T) {
	css := CSS("no-such-theme")
	if !strings.Contains(css, Default().Palette.Ink) {
		t.Error("CSS with an unknown default did not fall back to the default palette")
	}
}

func TestJSListsEveryTheme(t *testing.T) {
	js := JS("gruvbox")
	for _, th := range All() {
		if !strings.Contains(js, `id: "`+th.ID+`"`) {
			t.Errorf("theme.JS omits %q, so the picker cannot offer it", th.ID)
		}
		if !strings.Contains(js, `name: "`+th.Name+`"`) {
			t.Errorf("theme.JS omits the display name for %q", th.ID)
		}
	}
	if !strings.Contains(js, `window.HOSTVEIL_THEME_DEFAULT = "gruvbox"`) {
		t.Error("theme.JS does not carry the served default")
	}
	if !strings.Contains(js, "localStorage") {
		t.Error("theme.JS does not restore the saved choice")
	}
}
