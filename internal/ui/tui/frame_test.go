package tui

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// modeModels builds one populated model per mode at the given size. Every
// mode is represented, which the older per-mode assertions were not: the
// theme test's mode list is a hand-written subset, so preview, history and
// the rollback confirmation were never rendered by any assertion at all.
func modeModels(w, h int) map[string]*appModel {
	r := layoutReport()
	cps := []model.Checkpoint{
		{ID: "cp1", FindingID: "compose.ds018", Label: "Bind redis to loopback", Reversible: true,
			Files: []string{"/opt/stacks/cloud/docker-compose.yml"}, RestartService: "redis",
			Diff: "--- a\n+++ b\n-      - \"6379:6379\"\n+      - \"127.0.0.1:6379:6379\"\n"},
		{ID: "cp2", FindingID: "firewall.inactive", Label: "Enable ufw", Reversible: false},
	}
	preview := model.FixPreview{
		FindingID: "compose.ds018", Label: "Bind redis to loopback",
		Actions: []model.ActionPreview{
			{Index: 0, Label: "Publish on 127.0.0.1 only", Type: "edit", Path: "/opt/stacks/cloud/docker-compose.yml",
				Diff: "--- a\n+++ b\n-      - \"6379:6379\"\n+      - \"127.0.0.1:6379:6379\"\n"},
			{Index: 1, Label: "Remove the published port", Type: "exec",
				Warning:  "This recreates the container and there is no rollback checkpoint.",
				Commands: [][]string{{"docker", "compose", "up", "-d", "redis"}}},
		},
	}

	out := map[string]*appModel{}
	for md, name := range modeNames {
		m := &appModel{
			mode: md, width: w, height: h, report: r, selected: map[string]bool{},
			status: "Scanning…", checkpoints: cps, preview: preview,
			delta: model.Delta{Resolved: r.Findings[:1], New: r.Findings[1:2]},
		}
		m.rebuildActive()
		out[name] = m
	}
	return out
}

// modeNames is every mode, and the test below requires it to stay that way.
//
// It replaces a hand-written list inside modeModels that had fallen two
// behind the enum: modeForceConfirm and modeLayout were never built, so
// "every mode" meant eight of ten and the two screens most likely to be
// reached in a bad moment — a declined rollback, and the picker — were
// composed by nobody.
var modeNames = map[mode]string{
	modeScanning:        "scanning",
	modeList:            "list",
	modeDetail:          "detail",
	modePreview:         "preview",
	modeMessage:         "message",
	modeHistory:         "history",
	modeRollbackConfirm: "rollback",
	modeForceConfirm:    "force",
	modeTheme:           "theme",
	modeLayout:          "layout",
}

// A mode added without a name here is a mode no frame test renders, which is
// exactly how the previous gap opened. Walking the enum's own range is what
// makes that loud: modeCount is the only thing that has to be kept last.
func TestEveryModeIsNamedForTheFrameTests(t *testing.T) {
	for md := mode(0); md < modeCount; md++ {
		if modeNames[md] == "" {
			t.Errorf("mode %d has no entry in modeNames, so no frame test builds it", md)
		}
	}
	if len(modeNames) != int(modeCount) {
		t.Errorf("modeNames has %d entries for %d modes", len(modeNames), modeCount)
	}
}

// The frame must be exactly the terminal, in both axes, in every mode. This
// one table is the regression net for the whole composer: a mode that forgets
// to pad, one that overruns its budget, and one that emits a trailing newline
// all show up here rather than on someone's terminal.
func TestEveryModeFillsExactlyTheTerminal(t *testing.T) {
	sizes := []struct{ w, h int }{{200, 40}, {120, 34}, {100, 34}, {80, 24}, {60, 24}, {44, 20}}
	for _, sz := range sizes {
		for name, m := range modeModels(sz.w, sz.h) {
			lines := strings.Split(m.View().Content, "\n")
			if len(lines) != sz.h {
				t.Errorf("%s %dx%d: frame is %d lines, want %d", name, sz.w, sz.h, len(lines), sz.h)
			}
			for i, line := range lines {
				if got := visibleWidth(line); got > sz.w {
					t.Errorf("%s %dx%d: line %d is %d columns:\n  %q", name, sz.w, sz.h, i, got, line)
				}
			}
		}
	}
}

// The key hints live on the last row, always. Content-sized modes used to end
// wherever their content did, so on a short detail view the hints sat in the
// middle of the screen with an empty third below them.
func TestFooterIsPinned(t *testing.T) {
	want := map[string]string{
		"scanning": "ctrl+c quit", "list": "q quit", "detail": "q list",
		"preview": "n cancel", "message": "continue", "history": "q list",
		"rollback": "n cancel", "theme": "esc cancel",
	}
	for name, m := range modeModels(100, 34) {
		lines := strings.Split(m.View().Content, "\n")
		// Compared without styling: the key in each hint is drawn in the
		// accent and its description in slate, so the row is a run of escape
		// sequences with the words spread through it. What is being asserted
		// is where the hints are, not what colour they came out.
		last := plain(lines[len(lines)-1])
		if !strings.Contains(last, want[name]) {
			t.Errorf("%s: last row should end the key hints (%q), got %q", name, want[name], last)
		}
	}
}

// A model that has not seen a WindowSizeMsg has width and height 0. Drawing
// into that meant strings.Repeat with a negative count and a negative row
// budget; the fallback size is what keeps the first frame — and every model
// built as a bare literal — renderable.
func TestUnsetSizeRenders(t *testing.T) {
	for _, md := range []mode{modeScanning, modeList} {
		m := &appModel{mode: md}
		lines := strings.Split(m.View().Content, "\n")
		if len(lines) != fallbackHeight {
			t.Errorf("mode %v: unsized frame is %d lines, want %d", md, len(lines), fallbackHeight)
		}
		for _, line := range lines {
			if got := visibleWidth(line); got > fallbackWidth {
				t.Errorf("mode %v: unsized line is %d columns: %q", md, got, line)
			}
		}
	}
}

// The compact header is one row at every width — that is the whole point of
// it. The full strip costs three to five rows and is worth it on the list;
// repeating it over a detail view is what left an 80x24 terminal with half a
// screen of chrome.
func TestCompactHeaderIsOneRow(t *testing.T) {
	for _, w := range []int{200, 100, 80, 44, 20} {
		m := &appModel{mode: modeDetail, width: w, height: 30, report: layoutReport(), selected: map[string]bool{}}
		row := m.topRow("FIX PREVIEW")
		if strings.Contains(row, "\n") {
			t.Errorf("width=%d: compact header spans several rows: %q", w, row)
		}
		if got := visibleWidth(row); got > w {
			t.Errorf("width=%d: compact header is %d columns: %q", w, got, row)
		}
	}
}

// The full header earns its rows only while the list still has room to be a
// list. On a short or narrow terminal the axes strip wraps to five or nine
// rows, and keeping it there would leave the findings a couple of lines.
func TestFullHeaderDowngradesOnASmallTerminal(t *testing.T) {
	// Pinned to A · Split rather than the default, because the default is the
	// rail arrangement and the rail carries the same numbers — a header with no
	// strip in it there is the design, not a downgrade.
	roomy := &appModel{mode: modeList, width: 100, height: 34, report: layoutReport(),
		selected: map[string]bool{}, layout: "split"}
	roomy.rebuildActive()
	if n := len(roomy.headerRows(fullHeader(), 3)); n < 3 {
		t.Errorf("100x34 should keep the axes strip, got %d header rows", n)
	}

	cramped := &appModel{mode: modeList, width: 44, height: 20, report: layoutReport(),
		selected: map[string]bool{}, layout: "split"}
	cramped.rebuildActive()
	if n := len(cramped.headerRows(fullHeader(), 5)); n != 1 {
		t.Errorf("44x20 should fall back to the one-row header, got %d rows", n)
	}
}

// clip bounds a row that is already styled. truncate cannot: it measures
// runes, so it would charge a dozen columns for one escape sequence and cut
// through the middle of it.
func TestClipCountsCellsNotBytes(t *testing.T) {
	styled := "\x1b[38;2;255;0;0mhello\x1b[m world"
	got := clip(styled, 5)
	if visibleWidth(got) != 5 {
		t.Errorf("clip to 5 gave %d columns: %q", visibleWidth(got), got)
	}
	if !strings.HasSuffix(got, "\x1b[m") {
		t.Errorf("a cut through styled text must close the colour: %q", got)
	}
	if clip(styled, 100) != styled {
		t.Error("clip must return its input untouched when it already fits")
	}
	if clip(styled, 0) != "" {
		t.Error("clip to zero columns must render nothing")
	}
}

// The footer picks the key out of each hint and dims the rest, which is only
// safe while it can tell a key from a word. Two of the hints are sentences,
// and one of them is the confirmation for overwriting a file that rollback
// refused to touch — a footer offering `any` as the key there is worse than a
// footer with no colour at all.
//
// Asserted by rendering and asking which spans came back accented, because the
// bug is entirely in what got the colour.
func TestOnlyRealKeysAreHighlightedInTheFooter(t *testing.T) {
	m := modeModels(120, 30)["list"]

	for _, tc := range []struct {
		hint string
		keys []string // what must be accented
		not  []string // what must not
	}{
		{"↑/↓ move   enter details   f fix   space select", []string{"↑/↓", "enter", "f", "space"}, nil},
		{"press any key to continue", nil, []string{"press", "any"}},
		{"y overwrite anyway   any other key cancel", []string{"y"}, []string{"any"}},
		{"ctrl+c quit", []string{"ctrl+c"}, nil},
	} {
		got := m.styleHintLine(tc.hint)
		for _, k := range tc.keys {
			if !accented(m, got, k) {
				t.Errorf("%q: %q should be picked out as a key", tc.hint, k)
			}
		}
		for _, w := range tc.not {
			if accented(m, got, w) {
				t.Errorf("%q: %q was drawn as a key, and it is not one — the footer is "+
					"the only documentation these bindings have", tc.hint, w)
			}
		}
	}
}

// accented reports whether tok appears in rendered wearing the accent.
func accented(m *appModel, rendered, tok string) bool {
	return strings.Contains(rendered, m.sty().accent.Render(tok))
}
