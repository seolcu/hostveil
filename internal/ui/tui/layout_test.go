package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// visibleWidth is the rendered column count of a line, ignoring ANSI colour.
func visibleWidth(s string) int {
	var n int
	for i := 0; i < len(s); {
		if s[i] == 0x1b { // skip an escape sequence up to its final 'm'
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		_, size := decodeRune(s[i:])
		i += size
		n++
	}
	return n
}

func decodeRune(s string) (rune, int) {
	for i, r := range s {
		if i == 0 {
			return r, len(string(r))
		}
	}
	return 0, 1
}

// layoutReport has all nine domains, which is what a real host produces and
// what made the axes strip 213 columns wide.
func layoutReport() model.Report {
	axes := []model.ScoreAxis{}
	for _, id := range []string{"container", "ssh", "cve", "firewall", "ports", "accounts", "fileperms", "updates", "agent"} {
		axes = append(axes, model.ScoreAxis{ID: id, Label: id, Applicable: true, Score: 42})
	}
	axes[2].Applicable = false // an N/A axis
	axes[4].Degraded = true    // and a degraded one
	// Far more findings than fit any viewport under test: with a short list
	// the frame is bounded by the content rather than by the reservation, and
	// a wrong reservation never shows up.
	var fs []model.Finding
	for i := 0; i < 60; i++ {
		fs = append(fs, model.NewFinding("cve.outdated-image",
			"Image has vulnerabilities with published fixes", model.SeverityCritical,
			model.SourceCompose, model.RemediationAuto,
			model.WithService(fmt.Sprintf("cloud/nextcloud-%d", i))))
	}
	return model.Report{Findings: fs, Score: model.ScoreBreakdown{Overall: 42, Axes: axes}}
}

// The frame must fit the terminal it is drawn into. In alt-screen mode a line
// wider than the screen does not merely look wrong: it wraps, pushing every
// row below it down and off the bottom of the frame.
//
// Three separate defects violated this. The axes strip joined all nine
// domains into one 213-column row. truncate() returned its input unchanged
// whenever max < 4, so findingRow's m.width-46 went negative on a narrow
// terminal and stopped truncating titles at all — a narrower terminal
// produced longer lines. And the list reserved a hardcoded 8 rows for the
// chrome around it, which was wrong as soon as the header grew.
func TestFrameFitsTerminalWidth(t *testing.T) {
	r := layoutReport()
	for _, w := range []int{200, 120, 100, 80, 72, 60, 50, 44} {
		m := &appModel{
			mode: modeList, width: w, height: 30,
			report: r, selected: map[string]bool{},
			delta: model.Delta{Resolved: r.Findings[:1], New: r.Findings[1:2]},
		}
		m.active = m.report.Select(m.filter)
		for _, line := range strings.Split(m.View().Content, "\n") {
			if got := visibleWidth(line); got > w {
				t.Errorf("width=%d: line is %d columns:\n  %q", w, got, line)
			}
		}
	}
}

// The rows drawn plus the chrome around them must not exceed the terminal
// height, or the footer — which is where every key binding is documented —
// scrolls off the bottom.
func TestFrameFitsTerminalHeight(t *testing.T) {
	r := layoutReport()
	for _, h := range []int{40, 30, 24, 20} {
		for _, withDelta := range []bool{false, true} {
			m := &appModel{
				mode: modeList, width: 80, height: h,
				report: r, selected: map[string]bool{},
			}
			if withDelta {
				m.delta = model.Delta{Resolved: r.Findings[:1]}
			}
			m.active = m.report.Select(m.filter)
			got := strings.Count(m.View().Content, "\n") + 1
			if got > h {
				t.Errorf("height=%d delta=%v: frame is %d lines", h, withDelta, got)
			}
		}
	}
}

// The preview warning is the one place a fix says what it cannot undo, and it
// was rendered as a single unwrapped line. On a terminal narrower than the
// warning it ran off the edge and was clipped mid-sentence — in the exec case
// exactly at "There is no rollback", losing the reason that follows. Every
// line of every mode must fit the width it is drawn into.
func TestPreviewAndHistoryFitTerminalWidth(t *testing.T) {
	longWarn := "This recreates the container: the service goes down briefly and comes " +
		"back on a different image. There is no rollback checkpoint: exec fixes are " +
		"not file-backed, so hostveil cannot undo this."

	preview := &appModel{
		mode: modePreview, width: 80, height: 30, selected: map[string]bool{},
		preview: model.FixPreview{
			Label: "Update the image for nextcloud",
			Actions: []model.ActionPreview{
				{Index: 0, Label: "Pull the new image and recreate nextcloud now", Warning: longWarn,
					Type: "exec", Commands: [][]string{{"docker", "compose", "-f", "/opt/stacks/cloud/docker-compose.yml", "pull", "nextcloud"}}},
				{Index: 1, Label: "Download only", Warning: longWarn, Type: "exec",
					Commands: [][]string{{"docker", "compose", "pull", "nextcloud"}}},
			},
		},
	}

	cps := make([]model.Checkpoint, 20)
	for i := range cps {
		cps[i] = model.Checkpoint{
			ID: "cp", FindingID: "compose.ds018", Label: "Bind redis to loopback", Reversible: true,
		}
	}
	history := &appModel{mode: modeHistory, width: 72, height: 20, checkpoints: cps, report: layoutReport(), selected: map[string]bool{}}

	for name, m := range map[string]*appModel{"preview": preview, "history": history} {
		content := m.View().Content
		for _, line := range strings.Split(content, "\n") {
			if got := visibleWidth(line); got > m.width {
				t.Errorf("%s width=%d: line is %d columns:\n  %q", name, m.width, got, line)
			}
		}
		// The history list sizes itself to the terminal, so a wrong header
		// reservation makes it draw more rows than fit and the frame runs past
		// the bottom. (The preview is content-sized and not height-bounded.)
		if name == "history" {
			if got := strings.Count(content, "\n") + 1; got > m.height {
				t.Errorf("history height=%d: frame is %d lines", m.height, got)
			}
		}
	}
}
