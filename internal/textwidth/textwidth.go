// Package textwidth fits text to a terminal measured in the unit a
// terminal actually uses: display columns.
//
// It exists because three notions of "how wide is this" were in use at
// once, and only one of them was right. The TUI's padRight measured
// display columns; its truncate measured runes; its wrap and the CLI
// renderer's wrap both measured bytes. For ASCII all three agree, which is
// why the disagreement went unnoticed, and for anything else they diverge
// in opposite directions.
//
// Measured against a line of Hangul, where one character is three bytes,
// one rune, and two columns:
//
//	wrap(s, 40)     produced lines 24 columns wide — 40% of the terminal
//	                thrown away, because bytes overcount
//	truncate(s, 20) produced 34 columns — a 70% overflow of the budget it
//	                was handed, because runes undercount
//
// The second is the damaging one: truncate exists to make a cell fit the
// space computed for it, and returning something wider than that pushes
// the row past the edge of the terminal.
//
// Non-ASCII reaches these on ordinary hosts. Compose service names and file
// paths come from the operator, and `explain --ai` renders whatever the
// local model wrote — which for a non-English operator is not English.
package textwidth

import (
	"strings"

	"github.com/mattn/go-runewidth"
)

// narrow measures with East Asian Ambiguous characters counted as one
// column, and it is deliberately not runewidth's package default.
//
// That default is chosen from the environment: runewidth reads LANG and
// LC_ALL at init and sets EastAsianWidth when the locale is an East Asian
// one. Under ko_KR.UTF-8 it then reports two columns for "…", "→", "±" and
// "·" — all four of which hostveil draws, in the ellipsis truncate appends,
// the domain-status bullets, and the score arrows. The same binary would
// lay its screens out differently for an operator in Seoul and an operator
// in Berlin, from the same terminal width and the same findings.
//
// It also has to agree with lipgloss, which the TUI already uses for
// padRight and for measuring its own rows, and lipgloss counts those four
// as one column each. Two measurements that disagree are worse than either
// being wrong: truncate would cut to one budget while padRight padded to
// another, and the row would be over-full or ragged depending on the glyph.
// This condition matches lipgloss on every character the UI uses, and
// TestAgreesWithLipgloss in internal/ui/tui pins that.
var narrow = func() *runewidth.Condition {
	c := runewidth.NewCondition()
	c.EastAsianWidth = false
	return c
}()

// Of returns the number of terminal columns s occupies.
//
// Not len(), which counts bytes, and not len([]rune()), which counts code
// points: a Hangul syllable or a CJK ideograph occupies two columns and a
// combining mark occupies none.
func Of(s string) int { return narrow.StringWidth(s) }

// Truncate shortens s to at most max columns, ending with an ellipsis when
// anything was removed.
//
// The ellipsis costs a column of its own, so it is only used when there is
// room for it to be worth one; below that the text is simply cut. A max of
// zero or less yields the empty string rather than a bare ellipsis, since
// a caller with no room has nothing to say.
func Truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if Of(s) <= max {
		return s
	}
	if max < 4 {
		return narrow.Truncate(s, max, "")
	}
	return narrow.Truncate(s, max, "…")
}

// Wrap reflows s to lines of at most width columns, prefixing every line
// after the first with indent.
//
// Words are never split: a single word wider than the budget takes a line
// of its own and overruns it, which is the lesser of the two failures — a
// path or an identifier broken across lines cannot be copied.
//
// The indent is not counted against the width. Callers pass a width they
// have already reduced by the indent they want, which is how both callers
// used it before this moved here.
func Wrap(s string, width, minWidth int, indent string) string {
	if width < minWidth {
		width = minWidth
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := 0
	for i, w := range words {
		ww := Of(w)
		switch {
		case i == 0:
		case line+1+ww > width:
			b.WriteString("\n" + indent)
			line = 0
		default:
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += ww
	}
	return b.String()
}
