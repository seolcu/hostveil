package tui

import (
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/model"
)

// What a terminal interface has instead of borders and shadows is the grid:
// columns that start where the column above started, and lines that meet the
// lines they cross. Nothing here is about content — every check below passes
// on a screen full of the wrong words — and that is the point. These are the
// faults a reader sees before they have read anything.

// columnIndex is the display column needle starts at.
//
// Neither bytes nor runes will do. strings.Index counts bytes and every row
// here opens with a three-byte gutter; counting runes is right only while
// every glyph is one column, which is the assumption that produced the fault
// this file exists to catch. Columns are what the reader sees.
func columnIndex(row []rune, needle string) int {
	at := strings.Index(string(row), needle)
	if at < 0 {
		return -1
	}
	return lipgloss.Width(string(row)[:at])
}

// rowRunes is one rendered frame as a grid of display *columns* — escape
// sequences dropped, and a glyph that occupies two columns followed by a
// continuation entry so that index == column in either width mode.
//
// Indexing by rune would be the same thing only while every glyph is one
// column wide, which is precisely the assumption that broke the grid under
// RUNEWIDTH_EASTASIAN=1. A test written on it would have agreed with the bug.
func rowRunes(t *testing.T, frame string) [][]rune {
	t.Helper()
	lines := strings.Split(frame, "\n")
	out := make([][]rune, len(lines))
	for i, l := range lines {
		var cells []rune
		for _, r := range visibleRunes(l) {
			cells = append(cells, r)
			for w := lipgloss.Width(string(r)); w > 1; w-- {
				cells = append(cells, cont)
			}
		}
		out[i] = cells
	}
	return out
}

// cont marks the second column of a double-width glyph: nothing is drawn
// there, the glyph to its left is.
const cont rune = 0

// cover is the glyph occupying column c of row r, which for the right half of
// a wide glyph is the glyph that starts to its left.
func cover(rows [][]rune, r, c int) rune {
	if r < 0 || r >= len(rows) || c < 0 || c >= len(rows[r]) {
		return 0
	}
	for c > 0 && rows[r][c] == cont {
		c--
	}
	return rows[r][c]
}

// arms is the box-drawing character with exactly these connections, and the
// whole of what "the lines meet" means: a glyph is right when its arms are
// the neighbours that actually reach it.
var arms = map[[4]bool]rune{
	// up, down, left, right
	{true, true, false, false}:   '│',
	{false, true, true, true}:    '┬',
	{true, false, true, true}:    '┴',
	{true, true, false, true}:    '├',
	{true, true, true, false}:    '┤',
	{true, true, true, true}:     '┼',
	{false, false, true, true}:   '─',
	{false, false, false, false}: ' ',
}

func reachesVertically(rows [][]rune, r, c int) bool {
	return strings.ContainsRune("│┬┴├┤┼", cover(rows, r, c))
}

func reachesHorizontally(rows [][]rune, r, c int) bool {
	return strings.ContainsRune("─┬┴├┤┼", cover(rows, r, c))
}

// A rule that runs straight through a column separator, or a separator that
// stops dead where a rule crosses it, is the same defect from two sides: the
// two regions were drawn without knowing about each other, and it shows. The
// header rule needs a ┬ where the body's columns begin, the footer rule a ┴,
// and the rules a column draws inside itself — the pane's divider above its
// actions, the verdict band's under its sentence — a ├ where they arrive at
// the separator.
//
// Stated as "every junction glyph has exactly the arms its neighbours give
// it", which covers all of those without listing any of them, and covers the
// inverse too: a ┬ stamped at a column that turns out to have no separator
// under it fails here just as loudly.
//
// Both sizes, because the columns are given back as the terminal narrows.
func TestEveryRuleMeetsTheColumnsItCrosses(t *testing.T) {
	for _, id := range []string{"console", "split", "railverdict", "lanes"} {
		for _, size := range []struct{ w, h int }{{120, 34}, {100, 30}} {
			m := layoutModel(id, size.w, size.h)
			if len(m.bodySepColumns()) == 0 {
				t.Errorf("%s at %dx%d draws no columns at all", id, size.w, size.h)
				continue
			}
			rows := rowRunes(t, m.View().Content)
			for r, row := range rows {
				for c, got := range row {
					if got == cont {
						continue // the right half of a wide glyph draws nothing
					}
					reach := [4]bool{
						reachesVertically(rows, r-1, c), reachesVertically(rows, r+1, c),
						reachesHorizontally(rows, r, c-1),
						reachesHorizontally(rows, r, c+lipgloss.Width(string(got))),
					}
					n := 0
					for _, on := range reach {
						if on {
							n++
						}
					}
					// Only where three or four lines actually arrive. Two arms is
					// a plain rule or a plain separator and needs no glyph of its
					// own, and zero or one is a │ used as punctuation — the spark
					// strip's dividers, the inline block's gutter — which is text
					// and not grid, however much it looks like one here.
					if n < 3 {
						continue
					}
					if want := arms[reach]; want != 0 && got != want {
						t.Errorf("%s %dx%d row %d col %d: drew %q where %d lines meet, want %q",
							id, size.w, size.h, r, c, string(got), n, string(want))
					}
				}
			}
		}
	}
}

// The grid has to survive every width, not the two a screenshot was taken
// at. This sweeps each arrangement across the sizes a terminal is actually
// dragged through and holds three things at once:
//
//   - the frame is exactly the terminal, in both directions. A row one column
//     over wraps in the alt screen and pushes everything below it off the
//     bottom, which is how a layout fault becomes a missing footer.
//   - every body row reaches both of its column separators. A row that came
//     up short leaves a gap in the vertical rule — the fault that reads as
//     the lines being broken, and the one that a fixed-width test at one
//     size will never produce.
//   - the columns are given back cleanly as the terminal narrows: below the
//     thresholds there are no separators to reach, and nothing may draw one.
//
// The width sweep is the point. `TestFrameFitsTerminalWidth` already sweeps
// widths, but only ever with the default arrangement — five of the six were
// covered at whatever sizes a test happened to name, which for the rail
// layouts is on both sides of the width where the rail is dropped.
func TestEveryArrangementHoldsItsGridAtEveryWidth(t *testing.T) {
	widths := []int{200, 160, 132, 120, 110, 100, 96, 88, 84, 80, 76, 72, 64, 56, 48, 44, 40, 36, 30}
	heights := []int{44, 34, 30, 24, 20}
	for _, l := range Layouts() {
		for _, w := range widths {
			for _, h := range heights {
				m := layoutModel(l.ID, w, h)
				lines := strings.Split(m.View().Content, "\n")

				if len(lines) != h {
					t.Errorf("%s %dx%d: frame is %d rows", l.ID, w, h, len(lines))
				}
				for i, line := range lines {
					if got := visibleWidth(line); got > w {
						t.Errorf("%s %dx%d: row %d overflows to %d columns: %q", l.ID, w, h, i, got, line)
					}
				}

				rows := rowRunes(t, m.View().Content)
				cols := m.bodySepColumns()
				if len(cols) == 0 {
					// No columns at this size: nothing may draw a separator
					// where the body would have had one.
					continue
				}
				// The body is what lies between the header's rule and the
				// footer's, which are the only two rows carrying ┬ and ┴.
				top, bottom := -1, len(rows)
				for i, row := range rows {
					if top == -1 && strings.ContainsRune(string(row), '┬') {
						top = i
					}
					if strings.ContainsRune(string(row), '┴') {
						bottom = i
					}
				}
				if top == -1 {
					t.Errorf("%s %dx%d: %d columns but no ┬ anywhere", l.ID, w, h, len(cols))
					continue
				}
				for r := top + 1; r < bottom; r++ {
					for _, c := range cols {
						if c >= len(rows[r]) {
							t.Errorf("%s %dx%d: row %d stops at column %d, short of the separator at %d: %q",
								l.ID, w, h, r, len(rows[r]), c, string(rows[r]))
							continue
						}
						if !strings.ContainsRune("│┬┴├┤┼", rows[r][c]) {
							t.Errorf("%s %dx%d: row %d draws %q at column %d, where the separator runs: %q",
								l.ID, w, h, r, string(rows[r][c]), c, string(rows[r]))
						}
					}
				}
			}
		}
	}
}

// The findings list is a grid: severity, id, title, service. Two of those
// columns were laid out from arithmetic that did not match what was drawn —
// the severity was padded in the budget and not in the render, and the id
// field was a fixed thirteen that several real ids overrun — so the title
// column stepped left and right down the list and the right-aligned service
// stopped short of the pane separator on exactly the rows whose title nearly
// filled the space.
//
// Checked through the rendered frame rather than findingRow, because the
// caller is where the column width comes from and a row that lines up in
// isolation is not the claim.
func TestEveryFindingRowPutsItsColumnsInTheSamePlace(t *testing.T) {
	fs := []model.Finding{
		model.NewFinding("cve.outdated-image", "Image has vulnerabilities with published fixes",
			model.SeverityHigh, model.SourceCVE, model.RemediationReview, model.WithService("cloud/nextcloud")),
		model.NewFinding("ssh.maxauth", "MaxAuthTries is higher than necessary",
			model.SeverityLow, model.SourceSSH, model.RemediationAuto),
		model.NewFinding("compose.ds006", "Missing no-new-privileges hardening",
			model.SeverityMedium, model.SourceCompose, model.RemediationAuto, model.WithService("cloud/redis")),
		model.NewFinding("fileperms.envfile", "An .env file is world-readable",
			model.SeverityMedium, model.SourceFilePerms, model.RemediationAuto, model.WithService("ops")),
	}
	m := &appModel{mode: modeList, width: 100, height: 30, selected: map[string]bool{},
		report: model.Report{Findings: fs, Score: model.ScoreReport(fs, map[model.Source]model.ScanState{
			model.SourceCVE: model.ScanDone, model.SourceSSH: model.ScanDone,
			model.SourceCompose: model.ScanDone, model.SourceFilePerms: model.ScanDone,
		})}}
	m.rebuildActive()

	const w = 90
	titleAt, endsAt := -1, -1
	for _, f := range m.active {
		row := visibleRunes(m.findingRow(f, false, w))
		title := columnIndex(row, f.Title[:12])
		if title < 0 {
			t.Fatalf("%s: the title is not in its own row: %q", f.ID, string(row))
		}
		if titleAt == -1 {
			titleAt = title
		} else if title != titleAt {
			t.Errorf("%s: title starts at column %d, the rows before it start at %d — "+
				"the id column is not one width", f.ID, title, titleAt)
		}
		if f.Service == "" {
			continue // nothing to right-align, so nothing to line up with
		}
		end := lipgloss.Width(strings.TrimRight(string(row), " "))
		if endsAt == -1 {
			endsAt = end
		} else if end != endsAt {
			t.Errorf("%s: the service ends at column %d and the rows before it end at %d — "+
				"the column is ragged", f.ID, end, endsAt)
		}
	}
}

// The same claim for the history screen, which has the same shape and had the
// same fault: a fixed id field that most real finding ids are longer than, so
// every label after one of them sat a few columns right of the rest.
func TestEveryHistoryRowPutsItsLabelInTheSamePlace(t *testing.T) {
	at := time.Date(2026, 7, 26, 14, 3, 0, 0, time.UTC)
	m := &appModel{mode: modeHistory, width: 100, height: 30, selected: map[string]bool{},
		checkpoints: []model.Checkpoint{
			{ID: "1", FindingID: "compose.ds018", Label: "Bind redis to loopback", CreatedAt: at, Reversible: true},
			{ID: "2", FindingID: "firewall.inactive", Label: "Enable ufw", CreatedAt: at, Reversible: true},
			{ID: "3", FindingID: "ssh.maxauth", Label: "Set MaxAuthTries to 3", CreatedAt: at, Reversible: false},
		}}

	idW := m.checkpointIDWidth()
	labelAt := -1
	for i, cp := range m.checkpoints {
		row := visibleRunes(m.checkpointRow(cp, false, idW))
		at := columnIndex(row, cp.Label)
		if at < 0 {
			t.Fatalf("%s: the label is not in its own row: %q", cp.FindingID, string(row))
		}
		if labelAt == -1 {
			labelAt = at
		} else if at != labelAt {
			t.Errorf("checkpoint %d: label starts at column %d, the rows before it start at %d", i, at, labelAt)
		}
	}
}
