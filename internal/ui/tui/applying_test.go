package tui

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/seolcu/hostveil/internal/model"
)

// previewModel is a fix preview open on one finding, ready for y/n.
func previewModel(w, h int) *appModel {
	f := model.NewFinding("compose.ds018", "Datastore exposed", model.SeverityHigh,
		model.SourceCompose, model.RemediationAuto, model.WithService("cache"))
	return &appModel{
		mode: modePreview, width: w, height: h, selected: map[string]bool{},
		active:  []model.Finding{f},
		preview: model.FixPreview{FindingID: f.ID, Label: f.Title},
	}
}

// Confirming a fix used to leave the screen showing the exact frame it had
// before the keypress until the engine's answer arrived, however long that
// took — a Review fix can re-check its whole domain afterward, minutes for
// cve.*. modeApplying and its ticker exist so there is something on screen
// answering "is it hung?" the moment y is pressed, before the engine has
// said anything at all.
func TestConfirmingAFixEntersApplyingImmediately(t *testing.T) {
	m := tea.Model(previewModel(96, 34))

	next, cmd := m.Update(tea.KeyPressMsg(tea.Key{Text: "y"}))
	am := next.(*appModel)

	if am.mode != modeApplying {
		t.Fatalf("mode after y = %v, want modeApplying", am.mode)
	}
	if am.applyLabel == "" {
		t.Error("applyLabel is empty; the applying screen would name nothing")
	}
	if am.applyStartedAt.IsZero() {
		t.Error("applyStartedAt was never set")
	}
	if cmd == nil {
		t.Fatal("y should issue a command batching the apply with a ticker")
	}
	if _, ok := cmd().(tea.BatchMsg); !ok {
		t.Error("y's command should batch the apply and a ticker, not just the apply")
	}

	// The screen itself must already read "applying", not the frame the
	// preview left behind — the whole point is that this does not wait for
	// appliedMsg to say so.
	if view := am.View().Content; !strings.Contains(view, "APPLYING") {
		t.Errorf("view after y does not show the applying screen:\n%s", view)
	}
}

// The clock ticks while modeApplying is showing and stops re-arming the
// moment the model leaves it — the same rule scanning_test.go pins for
// modeScanning, now shared by the same ticker.
func TestTheApplyClockTicksAndStops(t *testing.T) {
	m := &appModel{mode: modeApplying, applyLabel: "Datastore exposed", width: 96, height: 34}
	m.applyStartedAt = time.Now().Add(-5 * time.Second)

	next, cmd := m.Update(elapsedTickMsg{})
	am := next.(*appModel)
	if am.applyElapsed < 5*time.Second {
		t.Errorf("applyElapsed = %v after a tick, want at least 5s", am.applyElapsed)
	}
	if cmd == nil {
		t.Error("the ticker should re-arm while still applying")
	}

	am.mode = modeMessage
	if _, cmd := am.Update(elapsedTickMsg{}); cmd != nil {
		t.Error("the ticker re-armed after the apply finished")
	}
}
