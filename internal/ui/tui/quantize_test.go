package tui

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

// The palettes are written as 24-bit hex and almost nobody sees them that way.
//
// hostveil's subject is servers, and a server is reached over SSH, which does
// not forward COLORTERM. Without it colorprofile degrades the TUI to the
// xterm-256 palette, so the hexes in internal/ui/theme are not colors that get
// drawn — they are inputs to a quantiser, and what the operator sees is
// whatever comes out of it.
//
// What comes out is not a rounding error. ansi.Convert256 maps a color into
// the 6x6x6 cube by truncating each channel, works out the nearest entry on
// the greyscale ramp, and returns whichever is closer *in HSLuv* — a choice
// its own source marks with "XXX: this is where it differs from tmux". For a
// mid-lightness color of moderate chroma the grey wins, and the color is drawn
// as grey.
//
// That is what shipped. One Dark's Crit (#e17079) and its Slate (#8e939b) both
// landed on index 246, so every High severity label, and the gutter beside it,
// came out the exact pixel value of the muted text next to it: 42 High
// findings on screen and not one red pixel anywhere in a screenshot of them.
// The severity that means "reachable now, from off-host, by someone holding
// nothing" was drawn in the color that means "this is the part you can skip".
//
// So the palettes are held to what the terminal actually renders, on both
// profiles, and this test is the only place that asks.
//
// It lives here rather than in internal/ui/theme because that package is pure
// data and string formatting by design — no lipgloss, no image/color — which
// is what lets the web dashboard depend on it. The quantiser is lipgloss's.

// chromatic roles must survive as colors. Each is a thing the design system
// says a color means: three heats that carry a severity, the fourth that
// carries the worst score band, safety, and the accent that carries structure.
// A grey here is not a duller version of the message, it is the absence of it.
func chromaticRoles(p theme.Palette) map[string]string {
	return map[string]string{
		"Crit":   p.Crit,
		"High":   p.High,
		"Med":    p.Med,
		"Safe":   p.Safe,
		"Accent": p.Accent,
	}
}

// distinctRoles must stay telling apart. Low is in the list but not in
// chromaticRoles: "no known path today" is allowed to be a grey, and is one on
// purpose — it just may not be *the same* grey as the muted text it sits
// beside, or as the body text.
func distinctRoles(p theme.Palette) map[string]string {
	m := chromaticRoles(p)
	m["Low"] = p.Low
	m["Bone"] = p.Bone
	m["Slate"] = p.Slate
	return m
}

// index256 is the palette entry a terminal without truecolor will actually
// draw for a hex, through the same code path the TUI renders with.
func index256(hex string) int {
	return int(ansi.Convert256(lipgloss.Color(hex)))
}

// isGrey reports whether an xterm-256 index is on the 24-step greyscale ramp.
// Indices 16..231 are the color cube; 232..255 are grey by construction.
func isGrey(i int) bool { return i >= 232 }

func TestEveryHeatSurvivesA256ColorTerminal(t *testing.T) {
	for _, th := range theme.All() {
		for role, hex := range chromaticRoles(th.Palette) {
			if i := index256(hex); isGrey(i) {
				t.Errorf("%s: %s is %s, which a 256-color terminal draws as xterm %d — "+
					"a grey. Over SSH, where COLORTERM is not forwarded, that is what "+
					"the operator sees. Raise its chroma until the cube beats the "+
					"greyscale ramp; the hue is what the theme is recognised by, so "+
					"move lightness and saturation rather than hue.",
					th.ID, role, hex, i)
			}
		}
	}
}

func TestNoTwoRolesCollapseOntoOneColor(t *testing.T) {
	for _, th := range theme.All() {
		seen := map[int]string{}
		for _, role := range []string{"Crit", "High", "Med", "Low", "Safe", "Accent", "Bone", "Slate"} {
			hex := distinctRoles(th.Palette)[role]
			i := index256(hex)
			if other, ok := seen[i]; ok {
				t.Errorf("%s: %s (%s) and %s (%s) both quantise to xterm %d, so on a "+
					"256-color terminal they are the same pixel value. Nord shipped "+
					"like this — its muted text and a Low finding were one colour, "+
					"and no amount of looking gets that distinction back.",
					th.ID, role, hex, other, distinctRoles(th.Palette)[other], i)
				continue
			}
			seen[i] = role
		}
	}
}

// The truecolor path is the one nobody was worried about, which is exactly why
// it is worth a line: a hex nudged until it clears the quantiser is still the
// color a modern terminal draws, and moving one far enough to fix 256 colors
// while wrecking 24-bit would be trading one operator's screen for another's.
func TestNudgingForThe256PathLeavesTruecolorAlone(t *testing.T) {
	for _, th := range theme.All() {
		for role, hex := range distinctRoles(th.Palette) {
			if len(hex) != 7 || hex[0] != '#' {
				t.Errorf("%s: %s is %q, which is not a #rrggbb literal", th.ID, role, hex)
				continue
			}
			if got := fmt.Sprintf("%v", lipgloss.Color(hex)); got == "" {
				t.Errorf("%s: %s (%s) does not parse as a color", th.ID, role, hex)
			}
		}
	}
}

// The two tests above hold the palette to the quantiser. This one holds the
// *rendering* to the palette, which is a different claim and the one that
// actually broke: a correct color is worth nothing if the row draws something
// else with it. The screenshot that started this had 42 High findings on it
// and not one red pixel, and no test in this package noticed, because they all
// compare rendered output against rendered output — both sides built from the
// same styles, so both sides are wrong together.
//
// So this renders a real row and puts it through colorprofile's writer at
// ANSI256, which is the code path an SSH session's bytes actually take, then
// reads the escape sequence back off the wire.
func TestAHighRowIsDrawnInAColorOverSSH(t *testing.T) {
	m := modeModels(200, 40)["list"]

	var high model.Finding
	found := false
	for _, f := range m.active {
		if f.Severity == model.SeverityHigh {
			high, found = f, true
			break
		}
	}
	if !found {
		t.Fatal("the fixture has no High finding, so this test cannot see the case it is for")
	}

	var buf bytes.Buffer
	w := &colorprofile.Writer{Forward: &buf, Profile: colorprofile.ANSI256}
	if _, err := io.WriteString(w, m.findingRow(high, false, 200)); err != nil {
		t.Fatalf("downsampling the row: %v", err)
	}

	matches := indexedForeground.FindAllStringSubmatch(buf.String(), -1)
	if len(matches) == 0 {
		t.Fatal("the row carries no 256-color foreground at all; either the profile " +
			"writer stopped downsampling or the row stopped being styled")
	}
	var got []int
	for _, mt := range matches {
		n, _ := strconv.Atoi(mt[1])
		got = append(got, n)
	}
	want := index256(theme.Default().Palette.Crit)
	if !slices.Contains(got, want) {
		t.Errorf("a High row drew foregrounds %v, none of them Crit (xterm %d). The "+
			"severity gutter and its label are what carry it, and a High finding "+
			"that borrows another role's color is not a High finding.", got, want)
	}
	// And the assertion that does not lean on the palette to grade the
	// palette. Everything above compares the row against Crit, so it passes
	// whatever Crit happens to be — including the grey that shipped. What a
	// reader needs is not that the row agrees with the theme file; it is that
	// the row arrives in a color at all.
	if isGrey(want) {
		t.Errorf("a High row's severity arrives as xterm %d, on the greyscale ramp. "+
			"Every other severity on the screen is a color, so this one reads as "+
			"the absence of one.", want)
	}
	if slate := index256(theme.Default().Palette.Slate); slices.Contains(got, slate) && want == slate {
		t.Errorf("High and the muted text both arrive as xterm %d", slate)
	}
}

var indexedForeground = regexp.MustCompile(`38;5;(\d+)`)
