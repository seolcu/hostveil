package tui

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/textwidth"
)

// Two measurements of the same row must agree, and this is the only package
// that imports both. padRight and the frame measure with lipgloss; truncate
// and wrap measure with textwidth. If they part company, truncate cuts to
// one budget while padRight pads to another and the row is over-full or
// ragged depending on which glyphs it happens to contain.
//
// They can part company by accident, because runewidth — which textwidth
// uses — chooses its default width table from LANG and LC_ALL at init.
// Under ko_KR.UTF-8 that default calls "…", "→", "±" and "·" two columns
// wide while lipgloss calls them one. textwidth pins an explicit condition
// to avoid it; this is what would notice if that pin were removed.
func TestTextwidthAgreesWithLipgloss(t *testing.T) {
	for _, s := range []string{
		// Every non-ASCII glyph the TUI draws.
		"…", "→", "±", "·", "✓", "✗", "⚠", "▚", "─", "~",
		// And content that reaches it from the host.
		"한글 서비스 이름", "混合 mixed content", "/home/seolcu/프로젝트/hostveil",
		"plain ascii", "", "  spaced  ",
		"✓ 2 resolved   + 1 new   ~ 3 changed",
	} {
		if got, want := textwidth.Of(s), lipgloss.Width(s); got != want {
			t.Errorf("textwidth.Of(%q) = %d but lipgloss.Width = %d — "+
				"truncate and padRight would disagree about the same row", s, got, want)
		}
	}
}

// The consequence, end to end: whatever truncate returns must fit the
// budget padRight is about to pad to, for every width and every script.
func TestTruncateFitsWhatPadRightPadsTo(t *testing.T) {
	for _, s := range []string{
		"한글은 한 글자가 두 칸을 차지합니다",
		"a fairly long ascii finding title that will not fit",
		"混合 mixed 텍스트 with ascii",
	} {
		for w := 0; w <= 30; w++ {
			cut := truncate(s, w)
			if got := lipgloss.Width(cut); got > w {
				t.Errorf("truncate(%q, %d) is %d columns by lipgloss — the row overflows", s, w, got)
			}
			if padded := padRight(cut, w); lipgloss.Width(padded) != w && cut != "" {
				t.Errorf("padRight(truncate(%q, %d)) is %d columns, want exactly %d",
					s, w, lipgloss.Width(padded), w)
			}
		}
	}
}

// And wrap must not hand the frame a line wider than the terminal.
func TestWrapLinesFitTheTerminal(t *testing.T) {
	for _, s := range []string{
		"한글로 된 설명이 길어지면 어떻게 되는지 확인하는 문장입니다 계속 이어집니다",
		"an english description that runs on for a while and needs to be reflowed neatly",
	} {
		for _, w := range []int{20, 40, 78} {
			for _, l := range strings.Split(wrap(s, w), "\n") {
				if got := lipgloss.Width(l); got > w {
					t.Errorf("wrap(_, %d) produced a %d-column line: %q", w, got, l)
				}
			}
		}
	}
}
