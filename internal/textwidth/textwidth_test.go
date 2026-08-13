package textwidth

import (
	"strings"
	"testing"
)

// One Hangul syllable is three bytes, one rune, and two columns. Every
// assertion below is a case where at least two of those disagree, which is
// the whole reason this package exists.
const ko = "한글은 한 글자가 두 칸을 차지하고 세 바이트입니다"

func TestOfCountsColumns(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"한", 2},
		{"한글", 4},
		{"a한b", 4},
		{"…", 1},
	} {
		if got := Of(tc.s); got != tc.want {
			t.Errorf("Of(%q) = %d, want %d", tc.s, got, tc.want)
		}
	}
	if got, bytes := Of(ko), len(ko); got == bytes {
		t.Errorf("Of and len agree at %d on Hangul; the fixture is not exercising the bug", got)
	}
	if got, runes := Of(ko), len([]rune(ko)); got == runes {
		t.Errorf("Of and rune count agree at %d on Hangul; the fixture is not exercising the bug", got)
	}
}

// The damaging half of the old behaviour: truncate measured runes, so a
// cell budgeted 20 columns came back 34 wide and pushed the row past the
// edge of the terminal.
func TestTruncateNeverExceedsItsBudget(t *testing.T) {
	for _, s := range []string{ko, "plain ascii text that is quite long indeed", "混合 mixed 텍스트 content", "…"} {
		for _, max := range []int{0, 1, 2, 3, 4, 5, 10, 20, 40, 200} {
			got := Truncate(s, max)
			if w := Of(got); w > max {
				t.Errorf("Truncate(%q, %d) = %q, %d columns — over budget", s, max, got, w)
			}
		}
	}
}

func TestTruncateKeepsWhatFits(t *testing.T) {
	if got := Truncate("abc", 10); got != "abc" {
		t.Errorf("Truncate = %q, want the string unchanged when it fits", got)
	}
	if got := Truncate(ko, 200); got != ko {
		t.Errorf("Truncate shortened a string that already fits")
	}
	if got := Truncate("abc", 0); got != "" {
		t.Errorf("Truncate(_, 0) = %q, want empty — no room means nothing to say", got)
	}
	// An ellipsis is only worth a column when there is room for it.
	if got := Truncate("abcdefgh", 10); got != "abcdefgh" {
		t.Errorf("Truncate = %q, want no ellipsis when nothing was cut", got)
	}
	if got := Truncate("abcdefgh", 5); !strings.HasSuffix(got, "…") {
		t.Errorf("Truncate = %q, want an ellipsis to mark what was cut", got)
	}
}

// The wasteful half: wrap measured bytes, so Hangul wrapped at roughly
// two-thirds of the width it was given.
func TestWrapFillsTheWidthItIsGiven(t *testing.T) {
	const width = 40
	lines := strings.Split(Wrap(ko, width, ""), "\n")
	if len(lines) < 2 {
		t.Fatalf("fixture did not wrap at width %d: %q", width, lines)
	}
	for i, l := range lines {
		if w := Of(l); w > width {
			t.Errorf("line %d is %d columns, over the %d budget: %q", i, w, width, l)
		}
	}
	// Every line but the last must be within one word of full, or the
	// wrapping is leaving the terminal empty — which is what counting bytes
	// did.
	for i, l := range lines[:len(lines)-1] {
		next := strings.Fields(lines[i+1])[0]
		if Of(l)+1+Of(next) <= width {
			t.Errorf("line %d is only %d of %d columns and the next word would have fit: %q",
				i, Of(l), width, l)
		}
	}
}

func TestWrapASCIIIsUnchangedInSpirit(t *testing.T) {
	const width = 40
	for _, l := range strings.Split(Wrap("the quick brown fox jumps over the lazy dog and keeps going", width, ""), "\n") {
		if w := Of(l); w > width {
			t.Errorf("line is %d columns, over %d: %q", w, width, l)
		}
	}
}

func TestWrapIndentsContinuationLines(t *testing.T) {
	out := Wrap("alpha beta gamma delta epsilon zeta eta theta", 20, "  ")
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected a wrap: %q", out)
	}
	if strings.HasPrefix(lines[0], "  ") {
		t.Error("the first line must not be indented")
	}
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "  ") {
			t.Errorf("continuation line not indented: %q", l)
		}
	}
}

// A word wider than the whole budget takes a line of its own and overruns
// it. Splitting it would be worse: a path or an identifier broken across
// lines cannot be copied.
func TestWrapDoesNotSplitAWordTooWideToFit(t *testing.T) {
	long := "/home/seolcu/프로젝트/hostveil/internal/textwidth/textwidth.go"
	out := Wrap("see "+long+" now", 10, "")
	if !strings.Contains(out, long) {
		t.Errorf("the long word was split:\n%s", out)
	}
}

func TestWrapEmptyInput(t *testing.T) {
	for _, s := range []string{"", "   ", "\t\n"} {
		if got := Wrap(s, 40, ""); got != "" {
			t.Errorf("Wrap(%q) = %q, want empty", s, got)
		}
	}
}

// The floor keeps a caller that computed a negative or absurd width from
// producing one word per line.
func TestWrapHasAMinimumWidth(t *testing.T) {
	for _, w := range []int{-10, 0, 3} {
		out := Wrap("alpha beta gamma delta", w, "")
		for _, l := range strings.Split(out, "\n") {
			if Of(l) > 8 && len(strings.Fields(l)) > 1 {
				t.Errorf("width %d produced an over-wide line: %q", w, l)
			}
		}
	}
}

// The locale trap. runewidth picks its default condition from LANG and
// LC_ALL at init, so its package-level StringWidth reports two columns for
// these under ko_KR.UTF-8 and one under en_US.UTF-8. Every one of them is
// drawn by hostveil, so using the default would lay the same screen out
// differently for different operators — and would disagree with lipgloss,
// which the TUI already uses to measure and pad the same rows.
func TestAmbiguousWidthIsNotLocaleDependent(t *testing.T) {
	for _, s := range []string{"…", "→", "±", "·", "✓", "⚠", "▚"} {
		if got := Of(s); got != 1 {
			t.Errorf("Of(%q) = %d, want 1 — an ambiguous-width glyph must not depend on the operator's locale", s, got)
		}
	}
	// Genuinely wide characters are still wide; the condition narrows only
	// the ambiguous class.
	for _, s := range []string{"한", "漢", "あ"} {
		if got := Of(s); got != 2 {
			t.Errorf("Of(%q) = %d, want 2", s, got)
		}
	}
}
