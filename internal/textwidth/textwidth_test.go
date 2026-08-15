package textwidth

import (
	"os"
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

// The locale trap, pinned at the rule rather than through the process
// environment.
//
// runewidth picks its default condition from LANG and LC_ALL at init, so its
// package-level StringWidth reports two columns for the ambiguous class under
// ko_KR.UTF-8 and one under en_US.UTF-8. Every one of those glyphs is drawn by
// hostveil, so using that default would lay the same screen out differently
// for two operators with the same terminal — and would disagree with lipgloss,
// which the TUI already uses to measure and pad the same rows.
//
// RUNEWIDTH_EASTASIAN is a different thing and is honoured: it is the operator
// saying their terminal draws that class wide, which is a fact about the
// terminal rather than about their language. This is the distinction the
// package doc argues for, and it is checked here directly — the seam exists
// (eastAsianEnv, eastAsianWidth) precisely so a test does not have to mutate a
// process-wide setting that was read at init.
func TestOnlyTheVariableTurnsOnEastAsianWidth(t *testing.T) {
	for _, v := range []string{"", "0", "false", "FALSE", "ko_KR.UTF-8", "ja_JP.UTF-8", "yes", "wide"} {
		if eastAsianWidth(v) {
			t.Errorf("%s=%q turned on east-asian width; only a value that parses as true may, "+
				"or the same binary lays out differently in Seoul and Berlin", eastAsianEnv, v)
		}
	}
	for _, v := range []string{"1", "true", "TRUE", "t"} {
		if !eastAsianWidth(v) {
			t.Errorf("%s=%q did not turn on east-asian width; ignoring it means disagreeing "+
				"with lipgloss, which reads the same variable", eastAsianEnv, v)
		}
	}
}

// And what Of does with the ambiguous class, in whichever mode this process is
// running in. Written against the rule rather than a constant, so it asserts
// something real under RUNEWIDTH_EASTASIAN=1 instead of being skipped there —
// which is how a whole class of layout defect stayed invisible until #711.
func TestAmbiguousWidthFollowsTheVariable(t *testing.T) {
	want := 1
	if eastAsianWidth(os.Getenv(eastAsianEnv)) {
		want = 2
	}
	// Genuinely East Asian Ambiguous, and all four are drawn by hostveil: the
	// ellipsis Truncate appends, the arrow in a delta, the ± in a score
	// change, and the domain-status bullet.
	for _, s := range []string{"…", "→", "±", "·"} {
		if got := Of(s); got != want {
			t.Errorf("Of(%q) = %d, want %d with %s=%q", s, got, want, eastAsianEnv, os.Getenv(eastAsianEnv))
		}
	}
	// And these are not, which is worth pinning because they look like they
	// should be. ✓ ⚠ ▚ are one column in both modes — and so is ░, while █ is
	// two, which is why internal/ui/tui builds a meter in columns rather than
	// dividing by one cell size. A change here would move that layout.
	for _, s := range []string{"✓", "⚠", "▚", "░"} {
		if got := Of(s); got != 1 {
			t.Errorf("Of(%q) = %d, want 1 in both modes", s, got)
		}
	}
	if got := Of("█"); got != want {
		t.Errorf("Of(%q) = %d, want %d — the filled block is ambiguous and the empty one "+
			"is not, which is the asymmetry the meter is laid out around", "█", got, want)
	}
	// Genuinely wide characters are still wide; the condition narrows only
	// the ambiguous class.
	for _, s := range []string{"한", "漢", "あ"} {
		if got := Of(s); got != 2 {
			t.Errorf("Of(%q) = %d, want 2", s, got)
		}
	}
}
