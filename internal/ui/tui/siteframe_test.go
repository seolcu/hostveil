package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// siteFramePath is the frame site/assets/tui.png was rendered from.
const siteFramePath = "testdata/site-frame.ans"

// TestSiteFrameIsCurrent is the check the image assets never had.
//
// Everything else the website says about hostveil is held to the code by a
// test: the domain names, the finding IDs, the fix column, the measured
// figures. The screenshots were outside all of it, and they drifted exactly
// the way an unchecked claim does — the published terminal frame kept showing
// a four-level severity scale for two releases after the scale became three,
// so the one part of the page a reader trusts on sight was the part saying
// something untrue.
//
// A PNG cannot be compared here: it comes out of scripts/ansi2png.py through
// PIL and a font, and neither is pinned, so a byte comparison would fail on a
// Pillow upgrade and say nothing about hostveil. What can be pinned is what
// the terminal actually drew, which is the thing the picture is a picture of.
// So the frame is committed, this re-renders it, and a difference fails the
// build with instructions rather than leaving a stale image to be noticed by
// a reader.
//
// Regenerating both, after reviewing the diff this test prints:
//
//	go test ./internal/ui/tui -run TestSnapshotDump \
//	  -args -test.v  # HOSTVEIL_SNAPSHOT=internal/ui/tui/testdata/site-frame.ans
//	python3 scripts/ansi2png.py internal/ui/tui/testdata/site-frame.ans site/assets/tui.png
func TestSiteFrameIsCurrent(t *testing.T) {
	want, err := os.ReadFile(siteFramePath)
	if err != nil {
		t.Fatalf("read the committed frame: %v", err)
	}
	got := siteFrame(t)
	if got == string(want) {
		return
	}

	t.Errorf("the TUI no longer draws the frame site/assets/tui.png was made from.\n"+
		"The published screenshot is now showing something hostveil does not do.\n\n"+
		"Regenerate both:\n"+
		"  HOSTVEIL_SNAPSHOT=%s go test ./internal/ui/tui -run TestSnapshotDump\n"+
		"  python3 scripts/ansi2png.py %s site/assets/tui.png\n\n%s",
		siteFramePath, siteFramePath, firstDifference(string(want), got))
}

// firstDifference reports the first line that differs, with the escape
// sequences made visible. A raw diff of two ANSI frames is unreadable — the
// colour codes are most of the bytes — and the failure that matters is
// usually one line of text, not the styling around it.
func firstDifference(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w == g {
			continue
		}
		return "first difference, line " + itoa(i+1) + ":\n" +
			"  committed: " + visible(w) + "\n" +
			"  rendered:  " + visible(g)
	}
	return "the frames differ in length only"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// visible replaces the escape character so a failure is readable in a test
// log, and keeps the codes rather than stripping them: a colour that changed
// is a real difference and the reader has to be able to see which one.
func visible(s string) string {
	return strings.ReplaceAll(s, "\x1b", "\\e")
}

// TestSiteFrameShowsWhatTheCaptionPromises holds the frame to the caption
// beside it. The interfaces page tells the reader this screenshot shows the
// severity mix and multi-select; a frame showing neither is a caption the
// picture contradicts.
//
// The labels come from model.AllSeverities rather than from a list written
// out here, because a list written out here is the thing that went stale in
// the first place: the frame kept a four-level scale for two releases after
// the scale became three, and any copy of the levels in this file would have
// gone stale with it.
func TestSiteFrameShowsWhatTheCaptionPromises(t *testing.T) {
	frame := siteFrame(t)
	// Case-folded: the rail draws the abbreviations upper-case and the model
	// stores them lower-case, and which of those is right is a styling
	// question this test has no business having an opinion about. What it
	// asserts is that every level hostveil has is visible in the picture.
	upper := strings.ToUpper(frame)
	for _, sev := range model.AllSeverities() {
		if !strings.Contains(upper, strings.ToUpper(sev.Abbr())) {
			t.Errorf("the published frame does not show the %s severity (%q), which the page's caption promises",
				sev, sev.Abbr())
		}
	}
	if !strings.Contains(frame, "marked") {
		t.Error("the published frame shows no multi-select, which the page's caption promises")
	}
}

func TestSiteFrameIsWhereTheGeneratorPutsIt(t *testing.T) {
	if _, err := os.Stat(filepath.Join("testdata", "site-frame.ans")); err != nil {
		t.Fatalf("the committed frame is missing: %v", err)
	}
}
