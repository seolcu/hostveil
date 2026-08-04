package glyph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/textwidth"
)

// The property the whole package rests on. The TUI's frame budgets columns
// and pads rows to them; a symbol two cells wide pushes its row past the
// edge of the terminal, and in alt-screen mode a wrapped row shoves every
// row below it off the bottom of the frame. Both sets, every symbol.
//
// The Nerd variants live in the Private Use Area, which runewidth treats as
// ambiguous and therefore one column under the narrow condition hostveil
// pins — so this measures what hostveil will *lay out*. A font that draws
// them double-width would still break the frame, which is why the package
// doc names the Mono patch as the requirement rather than "a Nerd Font".
func TestEverySymbolIsOneColumn(t *testing.T) {
	for _, s := range Symbols() {
		for set, got := range map[string]string{"plain": s.Plain, "nerd": s.Nerd} {
			if n := textwidth.Of(got); n != 1 {
				t.Errorf("%s/%s is %d columns (%q), want 1", set, s.Name, n, got)
			}
		}
	}
}

// A symbol declared without a row answers "?" from every renderer that asks
// for it, which is a question mark in the middle of the header rather than
// a compile error. Walking the const range is the only way to see that —
// iterating the table itself passes vacuously for exactly the symbol that
// is missing from it.
func TestEverySymbolConstHasARow(t *testing.T) {
	for sym := Brand; sym <= Cursor; sym++ {
		if got := Plain.Of(sym); got == "?" {
			t.Errorf("symbol %d has no row in defs", int(sym))
		}
	}
	if got := Plain.Of(Cursor + 1); got != "?" {
		t.Errorf("an out-of-range symbol returned %q, want the ? that makes the bug visible", got)
	}
}

// Two symbols that render the same character are two names for one thing,
// and a renderer picking between them is making a distinction the screen
// cannot show. Held per set, because the sets are allowed to disagree about
// how *many* distinct characters they have — they are not allowed to
// collapse two roles into one silently.
func TestSymbolsAreDistinctWithinASet(t *testing.T) {
	for _, set := range []struct {
		name string
		pick func(Entry) string
	}{
		{"plain", func(e Entry) string { return e.Plain }},
		{"nerd", func(e Entry) string { return e.Nerd }},
	} {
		seen := map[string]string{}
		for _, s := range Symbols() {
			g := set.pick(s)
			if prev, dup := seen[g]; dup {
				t.Errorf("%s: %s and %s both draw %q", set.name, prev, s.Name, g)
			}
			seen[g] = s.Name
		}
	}
}

// The plain set is the one that has to render on a stock terminal font, so
// nothing in it may be a Private Use codepoint — a PUA character there is a
// symbol that shows as tofu for everyone who did not opt in, which is the
// default. The nerd set is the reverse: a Nerd Font glyph that is not in
// the PUA is an ordinary character that gained nothing by opting in.
func TestSetsDrawFromTheRangesTheyClaim(t *testing.T) {
	inPUA := func(s string) bool {
		for _, r := range s {
			if r >= 0xE000 && r <= 0xF8FF {
				return true
			}
		}
		return false
	}
	for _, s := range Symbols() {
		if inPUA(s.Plain) {
			t.Errorf("plain/%s is a Private Use codepoint (%q); it must render without a patched font", s.Name, s.Plain)
		}
		if !inPUA(s.Nerd) {
			t.Errorf("nerd/%s is %q, which is not a Nerd Font codepoint — opting in buys nothing", s.Name, s.Nerd)
		}
	}
}

// Nerd Fonts patch the Font Awesome block at U+F000–U+F2FF, and that range
// is the oldest in the patch set and the one present in every build,
// including the Mono variants a terminal actually installs. Newer ranges are
// prettier and are missing from enough fonts that opting in would produce a
// row of tofu.
func TestNerdGlyphsComeFromTheFontAwesomeBlock(t *testing.T) {
	for _, s := range Symbols() {
		for _, r := range s.Nerd {
			if r < 0xF000 || r > 0xF2FF {
				t.Errorf("nerd/%s is U+%04X, outside the Font Awesome block every Nerd Font carries", s.Name, r)
			}
		}
	}
}

func TestLookupAndString(t *testing.T) {
	for _, name := range IDs() {
		s, ok := Lookup(name)
		if !ok {
			t.Fatalf("Lookup(%q) missed a listed set", name)
		}
		if s.String() != name {
			t.Errorf("Lookup(%q).String() = %q", name, s.String())
		}
	}
	if _, ok := Lookup("nerdfont"); ok {
		t.Error(`Lookup("nerdfont") resolved a set that does not exist`)
	}
	// The zero value has to be the safe one: a Set built without a choice is
	// what every bare struct literal in the TUI's tests holds.
	if (Set(0)) != Plain {
		t.Error("the zero Set is not Plain, so an unset field would opt a terminal in")
	}
}

// Precedence, and which layers are allowed to fail. Only the flag was typed
// just now; a stale environment variable or preference file falls back
// rather than refusing to start over a font.
func TestResolvePrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, "nerd"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, flag, env, dir string
		want                 Set
		wantErr              bool
	}{
		{name: "flag wins", flag: "plain", env: "nerd", dir: dir, want: Plain},
		{name: "env beats the saved choice", env: "plain", dir: dir, want: Plain},
		{name: "saved choice beats the default", dir: dir, want: Nerd},
		{name: "nothing set", want: Plain},
		{name: "bad flag is an error", flag: "bogus", want: Plain, wantErr: true},
		{name: "bad env falls back to saved", env: "bogus", dir: dir, want: Nerd},
		{name: "bad saved value falls back to plain", dir: t.TempDir(), want: Plain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.flag, tc.env, tc.dir)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Resolve error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("Resolve = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSaveRefusesAnUnknownSet(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, "nerdfont"); err == nil {
		t.Error("Save wrote an unknown set; Load would then have to reason about it")
	}
	if got := Load(dir); got != "" {
		t.Errorf("Load returned %q after a refused Save", got)
	}
}

// A preference file holding a set from some later build is not an error
// anywhere — it reads as "no preference".
func TestLoadIgnoresAStalePreference(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, prefFile), []byte("emoji\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Load(dir); got != "" {
		t.Errorf("Load = %q for a set this build does not have, want \"\"", got)
	}
	if got, err := Resolve("", "", dir); err != nil || got != Plain {
		t.Errorf("Resolve = %v, %v; a stale file must not fail the start", got, err)
	}
}
