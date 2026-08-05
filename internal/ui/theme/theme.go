// Package theme is the single source of truth for hostveil's colors.
//
// hostveil's design system is a monochrome console — bone text on ink,
// all-monospace, dense — where the ONLY things that carry color are risk
// (severity) and safety. A theme swaps the twelve hexes that system is drawn
// from; it does not change what any of them mean.
//
// The palettes used to be written down twice, as lipgloss colors in the TUI
// and as CSS custom properties in the web dashboard, each file claiming in a
// comment to match the other. Nothing enforced it. They live here now: the
// TUI builds its styles from these values and the dashboard's stylesheet is
// generated from them, so the two cannot drift.
//
// This package holds data and string formatting only — no lipgloss, no
// image/color, no engine. That is what lets both UIs depend on it without
// either one dragging the other's dependencies in.
package theme

import (
	"fmt"
	"sort"
	"strings"
)

// Palette is the twelve semantic roles the design system draws from.
// Every value is a lowercase "#rrggbb" string.
//
// Ink/Ink2/Ink3 are the background and its two raised surfaces; Line and
// Line2 are hairlines, with Line2 doubling as the selection ground; Bone and
// Slate are primary and muted text. The remaining five are the only ones that
// mean anything: four severity steps and safety.
type Palette struct {
	Ink   string
	Ink2  string
	Ink3  string
	Line  string
	Line2 string
	Bone  string
	Slate string
	Crit  string
	High  string
	Med   string
	Low   string
	Safe  string
}

// Theme is a named palette. ID is what a user types (--theme, HOSTVEIL_THEME,
// the saved preference, the dashboard's data-theme attribute); Name is what a
// picker shows.
type Theme struct {
	ID      string
	Name    string
	Palette Palette
}

// themes is the registry, in the order both pickers list them. One Dark is
// first because it is the default.
var themes = []Theme{
	{
		ID:   "onedark",
		Name: "One Dark",
		Palette: Palette{
			// Atom's One Dark. Eight of the twelve roles map onto its
			// published values unchanged; the other four needed a decision.
			// (Three of the four are the contrast lifts below; the fourth is
			// Bone, which is a judgement rather than a floor. This said
			// "nine ... three" and then described four changes, which is the
			// kind of arithmetic a comment gets to be wrong about forever.)
			//
			// Line is #181a1f, which is DARKER than the page. That is the look
			// and not a mistake: One Dark seams its panels rather than boxing
			// them in a bright hairline, and swapping it for a lighter rule is
			// most of what makes a One Dark port read as generic.
			//
			// Slate, Crit and Low are lifted, because One Dark's published
			// values do not clear the contrast floor this package holds every
			// theme to — the comment grey (#7f848e) lands at 3.73:1 on its own
			// background where 4.5 is required, the red (#e06c75) at 4.38, and
			// the Low grey at 3.39 against a floor of 3.5. Each is raised in
			// HSL lightness only, by the smallest step that clears it, so the
			// hue One Dark is recognised by is untouched. Nord needed the same
			// treatment for the same reason; see its entry below.
			//
			// Bone is One Dark's foreground (#abb2bf) lifted as well, though
			// that one is a judgement rather than a floor: an editor sets a few
			// hundred glyphs on screen and this sets thousands, and at editor
			// weight the denser view reads grey rather than written.
			Ink: "#282c34", Ink2: "#21252b", Ink3: "#2f343f",
			Line: "#181a1f", Line2: "#3e4451",
			Bone: "#c8ccd4", Slate: "#8e939b",
			Crit: "#e17079", High: "#d19a66", Med: "#e5c07b", Low: "#79808e",
			Safe: "#98c379",
		},
	},
	{
		ID:   "gruvbox",
		Name: "Gruvbox Dark",
		Palette: Palette{
			Ink: "#1d2021", Ink2: "#282828", Ink3: "#32302f",
			Line: "#3c3836", Line2: "#504945",
			Bone: "#ebdbb2", Slate: "#a89984",
			// Gruvbox's bright red and its "gray" both sit a step below the
			// contrast floor on the raised surface; lifted just past it.
			Crit: "#fb533f", High: "#fe8019", Med: "#fabd2f", Low: "#877a6f",
			Safe: "#b8bb26",
		},
	},
	{
		ID:   "nord",
		Name: "Nord",
		Palette: Palette{
			// Nord's Polar Night starts at #2e3440, which is the lightest
			// background of any theme here — light enough that its Aurora red
			// lands at 3:1 against it, and a Critical finding that reads as a
			// suggestion is worse than no theme at all. The ramp is shifted
			// down one step instead: #2e3440 becomes the raised surface and
			// the page sits below it, which buys enough room to keep Aurora
			// orange, yellow and green exactly as published.
			Ink: "#22262e", Ink2: "#2a2f3a", Ink3: "#2e3440",
			Line: "#3b4252", Line2: "#4c566a",
			Bone: "#eceff4", Slate: "#8d96af",
			Crit: "#cf818a", High: "#d08770", Med: "#ebcb8b", Low: "#76839d",
			Safe: "#a3be8c",
		},
	},
	{
		ID:   "catppuccin",
		Name: "Catppuccin Mocha",
		Palette: Palette{
			Ink: "#1e1e2e", Ink2: "#181825", Ink3: "#313244",
			Line: "#313244", Line2: "#45475a",
			Bone: "#cdd6f4", Slate: "#9399b2",
			Crit: "#f38ba8", High: "#fab387", Med: "#f9e2af", Low: "#6f7389",
			Safe: "#a6e3a1",
		},
	},
	{
		ID:   "tokyonight",
		Name: "Tokyo Night",
		Palette: Palette{
			Ink: "#1a1b26", Ink2: "#16161e", Ink3: "#24283b",
			Line: "#292e42", Line2: "#3b4261",
			Bone: "#c0caf5", Slate: "#9aa5ce",
			Crit: "#f7768e", High: "#ff9e64", Med: "#e0af68", Low: "#676ea1",
			Safe: "#9ece6a",
		},
	},
}

// All returns every theme, in picker order.
func All() []Theme {
	out := make([]Theme, len(themes))
	copy(out, themes)
	return out
}

// Default is the theme used when nothing has been chosen.
func Default() Theme { return themes[0] }

// Lookup finds a theme by ID.
func Lookup(id string) (Theme, bool) {
	for _, t := range themes {
		if t.ID == id {
			return t, true
		}
	}
	return Theme{}, false
}

// IDs lists every theme ID, for error messages and help text.
func IDs() []string {
	out := make([]string, 0, len(themes))
	for _, t := range themes {
		out = append(out, t.ID)
	}
	return out
}

// vars maps each palette role to its CSS custom property name. Sorted output
// keeps the generated stylesheet stable between builds.
func (p Palette) vars() map[string]string {
	return map[string]string{
		"--ink": p.Ink, "--ink-2": p.Ink2, "--ink-3": p.Ink3,
		"--line": p.Line, "--line-2": p.Line2,
		"--bone": p.Bone, "--slate": p.Slate,
		"--crit": p.Crit, "--high": p.High, "--med": p.Med, "--low": p.Low,
		"--safe": p.Safe,
	}
}

func (p Palette) block(selector string) string {
	v := p.vars()
	names := make([]string, 0, len(v))
	for name := range v {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	fmt.Fprintf(&b, "%s {\n", selector)
	// Every palette here is bone-on-ink, and the browser has no way to know
	// that from custom properties: the widgets it draws itself — a checkbox,
	// a <select>'s dropdown, a scrollbar — follow color-scheme, not --ink. Left
	// unset they come out of the light default, which is why an unticked
	// batch-select box was a white square sitting in the middle of a dark
	// findings list. Written per block rather than once on :root so it travels
	// with the palette it describes; TestEveryPaletteIsDark holds the claim,
	// and a light theme would have to answer it here.
	b.WriteString("  color-scheme: dark;\n")
	for _, name := range names {
		fmt.Fprintf(&b, "  %s: %s;\n", name, v[name])
	}
	b.WriteString("}\n")
	return b.String()
}

// CSS renders every palette as custom properties. The theme named by
// defaultID (falling back to Default) is emitted bare on :root, so the page
// paints correctly before any script runs; each theme also gets a
// data-theme block so the picker can switch to it — including the default,
// which is how switching back works.
func CSS(defaultID string) string {
	def, ok := Lookup(defaultID)
	if !ok {
		def = Default()
	}

	var b strings.Builder
	b.WriteString("/* Generated by internal/ui/theme — do not edit by hand. */\n")
	fmt.Fprintf(&b, "/* default: %s */\n", def.ID)
	b.WriteString(def.Palette.block(":root"))
	for _, t := range themes {
		b.WriteString("\n")
		b.WriteString(t.Palette.block(fmt.Sprintf(":root[data-theme=%q]", t.ID)))
	}
	return b.String()
}

// JS renders the theme list and the applier that runs before first paint.
//
// It is served as its own file rather than inlined into the page because the
// dashboard's Content-Security-Policy is default-src 'self', which blocks
// inline script. Loading it as a blocking script in <head> is what keeps the
// saved theme from flashing the default palette on every page load.
func JS(defaultID string) string {
	var b strings.Builder
	b.WriteString("/* Generated by internal/ui/theme — do not edit by hand. */\n")
	b.WriteString("window.HOSTVEIL_THEMES = [\n")
	for _, t := range themes {
		fmt.Fprintf(&b, "  {id: %q, name: %q},\n", t.ID, t.Name)
	}
	b.WriteString("];\n")
	fmt.Fprintf(&b, "window.HOSTVEIL_THEME_DEFAULT = %q;\n", defaultOrFallback(defaultID))
	b.WriteString(`try {
  var saved = localStorage.getItem("hostveil.theme");
  if (saved && window.HOSTVEIL_THEMES.some(function (t) { return t.id === saved; })) {
    document.documentElement.setAttribute("data-theme", saved);
  }
} catch (e) { /* private mode: the served default still applies */ }
`)
	return b.String()
}

func defaultOrFallback(id string) string {
	if t, ok := Lookup(id); ok {
		return t.ID
	}
	return Default().ID
}
