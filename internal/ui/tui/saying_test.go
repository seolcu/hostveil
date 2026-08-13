package tui

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/glyph"
	"github.com/seolcu/hostveil/internal/model"
)

// The three summaries draw their tick from the glyph table.
//
// They were package-level functions, so they could not reach the set the model
// holds and each wrote a literal "✓". With --glyphs nerd every other tick on
// the screen was a patched glyph and these three were not — one interface
// drawing two alphabets, which is the drift internal/glyph exists to make
// impossible.
//
// The assertion is that the plain and Nerd renderings differ, not that either
// is a particular character: naming the codepoint here would make this test
// agree with the table by copying it.
func TestEverySummaryDrawsItsTickFromTheGlyphTable(t *testing.T) {
	outcome := model.FixOutcome{Success: true, CheckpointID: "cp1", RestartHint: "redis"}
	rollback := model.RollbackOutcome{RestoredFiles: []string{"/etc/ssh/sshd_config"}}
	batch := model.BatchOutcome{Message: "Applied 3 fixes."}

	for name, summarise := range map[string]func(*appModel) string{
		"applySummary":    func(m *appModel) string { return m.applySummary(outcome) },
		"rollbackSummary": func(m *appModel) string { return m.rollbackSummary(rollback) },
		"batchSummary":    func(m *appModel) string { return m.batchSummary(batch) },
	} {
		plainSet := summarise(&appModel{gl: glyph.Plain})
		nerdSet := summarise(&appModel{gl: glyph.Nerd})
		if plainSet == nerdSet {
			t.Errorf("%s renders identically in both glyph sets, so it is not asking the table", name)
		}
		if !strings.HasPrefix(plainSet, glyph.Plain.Of(glyph.OK)) {
			t.Errorf("%s does not lead with the table's tick: %q", name, plainSet)
		}
		if !strings.HasPrefix(nerdSet, glyph.Nerd.Of(glyph.OK)) {
			t.Errorf("%s does not lead with the table's Nerd tick: %q", name, nerdSet)
		}
	}
}

// A summary is several facts, and the message screen keeps them apart.
//
// They used to be concatenated into one sentence, which the screen then
// word-wrapped: what happened, what it cost, how to undo it and what to
// restart ran together, and the break landed wherever the column happened to
// fall — "You may need to / restart 'redis'."
//
// textwidth.Wrap builds from strings.Fields, which treats a newline as a
// space, so a renderer that wrapped the whole status at once would silently
// undo this. That is the regression this pins.
func TestTheMessageScreenKeepsTheFactsApart(t *testing.T) {
	m := &appModel{mode: modeMessage, width: 96, height: 34, selected: map[string]bool{}}
	m.status = m.applySummary(model.FixOutcome{
		Success: true, CheckpointID: "cp1", RestartHint: "redis",
		NewScore: model.ScoreBreakdown{Overall: 61, Applicable: true},
	})

	// From the message's own first line, so the header and the footer — which
	// are the frame's, not the message's — do not count as facts.
	var found []string
	for _, line := range strings.Split(plain(m.View().Content), "\n") {
		s := strings.TrimSpace(line)
		if len(found) == 0 && !strings.Contains(s, "Fix applied.") {
			continue
		}
		if s == "" && len(found) > 0 {
			continue
		}
		if strings.Contains(s, "press any key") {
			break
		}
		found = append(found, s)
	}
	if len(found) < 4 {
		t.Fatalf("the message rendered as %d lines, so the facts were reflowed into a paragraph:\n%v", len(found), found)
	}
	for i, want := range []string{"Fix applied.", "New score: 61/100", "Press h to undo it.", "restart 'redis'"} {
		if !strings.Contains(found[i], want) {
			t.Errorf("line %d is %q, want it to carry %q", i, found[i], want)
		}
	}
}

// The screen an operator reads immediately before pressing y.
//
// It showed the diff and the fix's label and nothing else — not the finding it
// repairs, not whether hostveil considers the fix safe to apply unattended,
// not the file it edits, and not whether it can be undone. The rollback
// confirmation, which asks a strictly smaller question, said all of that.
//
// The reversibility line matters most in pairs: an exec action already carries
// a warning saying there is no checkpoint, so saying only the alarming half
// left the operator to infer the safe half from its absence.
func TestThePreviewSaysWhatItIsBeforeItAsks(t *testing.T) {
	m := &appModel{mode: modePreview, width: 96, height: 34, selected: map[string]bool{}}
	m.preview = model.FixPreview{
		FindingID: "compose.ds018", Label: "Bind redis to loopback", Kind: model.RemediationAuto,
		Actions: []model.ActionPreview{{Index: 0, Label: "Publish on 127.0.0.1 only", Type: "edit",
			Path: "/opt/stacks/cloud/docker-compose.yml",
			Diff: "--- a\n+++ b\n@@ -1 +1 @@\n-      - \"6379:6379\"\n+      - \"127.0.0.1:6379:6379\"\n"}},
	}
	got := plain(m.View().Content)

	for _, want := range []string{
		"COMPOSE.DS018",                        // which finding this repairs
		"AUTO",                                 // and how much judgement hostveil thinks it needs
		"/opt/stacks/cloud/docker-compose.yml", // the file it edits
		"backs the file up",                    // and that it can be undone
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the preview does not say %q before asking to apply:\n%s", want, got)
		}
	}
}

// An exec action must not claim a backup it does not take. Commands are not
// file-backed, so there is nothing to restore and the warning says so — the
// reassurance belongs to the edit case only.
func TestThePreviewPromisesNoBackupForACommand(t *testing.T) {
	m := &appModel{mode: modePreview, width: 96, height: 34, selected: map[string]bool{}}
	m.preview = model.FixPreview{
		FindingID: "cve.outdated-image", Label: "Update the image", Kind: model.RemediationReview,
		Actions: []model.ActionPreview{{Index: 0, Label: "Pull and recreate", Type: "exec",
			Warning:  "There is no rollback checkpoint — exec fixes are not file-backed.",
			Commands: [][]string{{"docker", "compose", "pull", "nextcloud"}}}},
	}
	got := plain(m.View().Content)
	if strings.Contains(got, "backs the file up") {
		t.Errorf("the preview promises a backup for a command that writes no file:\n%s", got)
	}
	if !strings.Contains(got, "no rollback checkpoint") {
		t.Errorf("the preview does not say the command cannot be undone:\n%s", got)
	}
}
