// Package glyph is the one table of the symbols hostveil's terminal
// interfaces draw, and the two sets they can be drawn from.
//
// A terminal cannot be asked what font it is using. There is no escape
// sequence for it and no width probe that distinguishes a present glyph
// from a missing one, because a terminal draws tofu in the same single cell
// it would have drawn the glyph in. So this is an opt-in, not a detection:
// the operator says they have a Nerd Font and hostveil believes them,
// exactly the way every other tool in this space handles it.
//
// The default is therefore Plain, which is every symbol hostveil drew
// before this package existed — nothing about an ordinary run changes.
//
// Both sets are held to one column per symbol. That is the load-bearing
// property, not a nicety: the TUI's frame arithmetic budgets columns, and a
// symbol two cells wide pushes its row past the edge of the terminal, which
// in alt-screen mode wraps and shoves every row below it off the bottom.
// TestEverySymbolIsOneColumn pins it for both sets.
//
// The Nerd variants come from the Font Awesome block (U+F000–U+F2FF), for
// two reasons that were checked rather than assumed. It is the oldest range
// in the patch set, so it is present everywhere — a newer, prettier
// codepoint that half the fonts lack is worse than no support at all,
// because the operator opted in and got a row of tofu. And it is the range
// that stays one cell wide: the glyphs that go double-width in a
// non-Mono build are the Powerline, Devicon and Material ranges, not this
// one, so hostveil does not have to care which variant is installed.
//
// Verified against v3.4.0 of JetBrains Mono, Hack, FiraCode and Meslo — 18
// files, Mono and non-Mono — by reading each font's cmap and hmtx: every
// symbol below is present in all of them, and every one has the same
// advance as an ASCII 'M'.
package glyph

import (
	"fmt"
	"strings"
)

// Set is which of the two tables to draw from. The zero value is Plain, so
// anything constructed without a choice — and every model built as a bare
// struct literal in the tests — renders the way hostveil always has.
type Set int

const (
	Plain Set = iota
	Nerd
)

// Symbol names one drawn thing. It is what a renderer asks for; which
// character it turns into is this package's business.
type Symbol int

const (
	// Brand is the mark in the TUI's header, the terminal's stand-in for
	// the chip that favicon.svg and the site header draw.
	Brand Symbol = iota
	// OK marks something resolved, applied, or passing.
	OK
	// Warning heads the sentence a preview uses to say what it cannot undo.
	Warning
	// Failed, Partial and Skipped are the three ways a domain can fall
	// short, in the order coverage notices list them.
	Failed
	Partial
	Skipped
	// Cursor marks the row a picker is on.
	Cursor
)

// def is one symbol's row. Every symbol is declared here once, with both
// spellings side by side, so the two sets cannot drift into disagreeing
// about which symbols exist — which is what a second table would allow and
// what nothing would then notice.
type def struct {
	sym   Symbol
	name  string
	plain string
	nerd  string
}

// defs is keyed by the constant's value through the lookup below, never by
// slice position: adding a symbol in the middle must not silently renumber
// what every renderer already asks for.
var defs = []def{
	// ▣ rather than the ▚ this replaced. The old one is a quadrant block,
	// which is missing from enough monospace fonts that it rendered as tofu;
	// ▣ is Geometric Shapes, is in nearly everything, and is the closest a
	// single cell gets to the mark itself — a package with a core in it.
	{Brand, "brand", "▣", ""},     // nf-fa-microchip
	{OK, "ok", "✓", ""},           // nf-fa-check
	{Warning, "warning", "⚠", ""}, // nf-fa-exclamation_triangle
	{Failed, "failed", "!", ""},   // nf-fa-times_circle
	{Partial, "partial", "~", ""}, // nf-fa-exclamation_circle
	{Skipped, "skipped", "·", ""}, // nf-fa-minus_circle
	{Cursor, "cursor", "›", ""},   // nf-fa-angle_right
}

// There is deliberately no arrow row. "→" appears once, inside the
// evidence-change detail a delta prints, three call frames below anything
// holding an Options — and the Nerd arrow is a slightly longer arrow. A row
// nothing asks for is a row that goes stale unnoticed, which is the same
// argument the layout picker's dead-entry test makes.

// Of returns the symbol as this set spells it. An unknown symbol returns
// "?" rather than the empty string: a renderer that asks for something that
// does not exist has a bug, and a blank cell hides it while a question mark
// in the middle of the header does not.
func (s Set) Of(sym Symbol) string {
	for _, d := range defs {
		if d.sym != sym {
			continue
		}
		if s == Nerd {
			return d.nerd
		}
		return d.plain
	}
	return "?"
}

// String is the stable lowercase name, which is what --glyphs takes and
// what the preference file holds.
func (s Set) String() string {
	if s == Nerd {
		return "nerd"
	}
	return "plain"
}

// Lookup resolves a name to a set.
func Lookup(name string) (Set, bool) {
	switch strings.TrimSpace(name) {
	case "plain":
		return Plain, true
	case "nerd":
		return Nerd, true
	}
	return Plain, false
}

// IDs lists every set name, for flag help and error messages.
func IDs() []string { return []string{"plain", "nerd"} }

// Entry is one row of the table, read out. Name is the stable lowercase
// name a test or an error message uses.
type Entry struct {
	Symbol      Symbol
	Name        string
	Plain, Nerd string
}

// Symbols lists every symbol with both spellings. It exists so a test can
// walk the table and a future picker could show it, without either one
// copying the rows out again.
func Symbols() []Entry {
	out := make([]Entry, 0, len(defs))
	for _, d := range defs {
		out = append(out, Entry{d.sym, d.name, d.plain, d.nerd})
	}
	return out
}

type unknownSetError struct{ name string }

func (e *unknownSetError) Error() string {
	return fmt.Sprintf("unknown glyph set %q; available: %s", e.name, strings.Join(IDs(), ", "))
}
