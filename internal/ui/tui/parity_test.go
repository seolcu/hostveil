package tui

import (
	"strings"
	"testing"

	// This test file imports internal/history to build the exact error the
	// engine returns when it declines a rollback. The layering test scans
	// production files only, and asserting against a stand-in would be
	// asserting against something core.IsExternalEdit does not actually
	// recognise — which is the bug this covers.
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// The engine has emitted per-domain progress since the CLI display was
// built for it, and the TUI passed nil and threw every event away. On a
// host with many images a scan takes minutes, and the screen said
// "Scanning…" for all of it — a display that cannot distinguish "still
// working" from "hung" is the one place this is not decoration.
func TestScanProgressNamesTheDomainsStillWorking(t *testing.T) {
	m := &appModel{mode: modeScanning, width: 100, height: 24, selected: map[string]bool{}}
	m.scanRunning = map[model.Source]bool{}

	m.noteScanEvent(model.ScanEvent{Source: model.SourceCVE, State: model.ScanRunning})
	m.noteScanEvent(model.ScanEvent{Source: model.SourceSSH, State: model.ScanRunning})
	if !strings.Contains(m.status, model.SourceCVE.Label()) ||
		!strings.Contains(m.status, model.SourceSSH.Label()) {
		t.Errorf("status does not name the running domains: %q", m.status)
	}

	// A finished checker leaves the line and joins the count. Skipped and
	// Degraded are outcomes, not failures to report, so they finish too.
	m.noteScanEvent(model.ScanEvent{Source: model.SourceSSH, State: model.ScanDone})
	if strings.Contains(m.status, model.SourceSSH.Label()) {
		t.Errorf("a finished domain is still listed as running: %q", m.status)
	}
	if !strings.Contains(m.status, "1 done") {
		t.Errorf("status does not report progress: %q", m.status)
	}

	m.noteScanEvent(model.ScanEvent{Source: model.SourceCVE, State: model.ScanSkipped})
	if m.scanDone != 2 {
		t.Errorf("scanDone = %d, want 2 — a skipped domain still finished", m.scanDone)
	}
	if strings.Contains(m.status, ",") {
		t.Errorf("nothing is running, so nothing should be listed: %q", m.status)
	}
}

// The wiring, not just the fold: an event has to reach the model through
// Update. The TUI's scan already emitted these into a nil channel, so a
// version of this that only exercised noteScanEvent would pass against the
// exact bug being fixed.
func TestScanProgressReachesTheModelThroughUpdate(t *testing.T) {
	m := &appModel{mode: modeScanning, width: 100, height: 24, selected: map[string]bool{}}
	m.scanCh = make(chan model.ScanEvent, 1)

	m.Update(scanProgressMsg{event: model.ScanEvent{Source: model.SourceCVE, State: model.ScanRunning}})
	if !strings.Contains(m.status, model.SourceCVE.Label()) {
		t.Errorf("an event through Update did not reach the status line: %q", m.status)
	}
	if !strings.Contains(m.View().Content, model.SourceCVE.Label()) {
		t.Errorf("the scanning screen does not show it:\n%s", m.View().Content)
	}

	// Progress that lands after the report is stale by definition: the scan
	// is over and the list is drawn. It must not overwrite the screen the
	// user is now reading.
	m.mode = modeList
	before := m.status
	m.Update(scanProgressMsg{event: model.ScanEvent{Source: model.SourceSSH, State: model.ScanRunning}})
	if m.status != before {
		t.Errorf("a late event rewrote the status after the scan finished: %q", m.status)
	}
}

// Map iteration order would make the line jitter on every redraw, which
// reads as the screen malfunctioning rather than as work progressing.
func TestScanProgressIsStablyOrdered(t *testing.T) {
	build := func() string {
		m := &appModel{mode: modeScanning, scanRunning: map[model.Source]bool{}}
		for _, s := range model.AllSources() {
			m.noteScanEvent(model.ScanEvent{Source: s, State: model.ScanRunning})
		}
		return m.status
	}
	first := build()
	for i := 0; i < 20; i++ {
		if got := build(); got != first {
			t.Fatalf("status is not stable across renders:\n %q\n %q", first, got)
		}
	}
}

// A declined rollback is a question, not a failure. The engine refuses when
// the file changed after hostveil wrote it, the CLI has offered --force
// since 3.4, and the dashboard's server has accepted it since the token
// landed — but in the TUI the answer was "Rollback failed" and a dead end.
func TestDeclinedRollbackOffersToForce(t *testing.T) {
	m := &appModel{mode: modeHistory, width: 100, height: 24, selected: map[string]bool{},
		checkpoints: []model.Checkpoint{{ID: "cp1", Label: "Bind redis to loopback",
			Files: []string{"/opt/stacks/cloud/docker-compose.yml"}, Reversible: true}}}

	m.Update(rolledBackMsg{err: &history.ExternalEditError{CheckpointID: "cp1", Path: "/opt/stacks/cloud/docker-compose.yml"}})
	if m.mode != modeForceConfirm {
		t.Fatalf("mode = %v, want modeForceConfirm — a decline must offer the override", m.mode)
	}

	// The screen has to say the two things the operator cannot recover
	// from not knowing: the file changed, and forcing cannot be undone.
	body := m.View().Content
	for _, want := range []string{"discarding those changes", "cannot be undone"} {
		if !strings.Contains(body, want) {
			t.Errorf("the declined screen does not say %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "/opt/stacks/cloud/docker-compose.yml") {
		t.Errorf("the declined screen does not name the file it would overwrite:\n%s", body)
	}
}

// Forcing is destructive and one-way, so only an explicit yes may do it.
// Anything else cancels — the same rule keyRollbackConfirm follows, and for
// a stronger reason.
func TestForceConfirmTakesOnlyAnExplicitYes(t *testing.T) {
	for _, key := range []string{"n", "esc", "q", "enter", " "} {
		m := &appModel{mode: modeForceConfirm, selected: map[string]bool{},
			checkpoints: []model.Checkpoint{{ID: "cp1", Reversible: true}}}
		if _, cmd := m.keyForceConfirm(key); cmd != nil {
			t.Errorf("key %q issued a command; only \"y\" may force", key)
		}
		if m.mode != modeList {
			t.Errorf("key %q left mode = %v, want modeList", key, m.mode)
		}
	}

	m := &appModel{mode: modeForceConfirm, selected: map[string]bool{},
		checkpoints: []model.Checkpoint{{ID: "cp1", Reversible: true}}}
	if _, cmd := m.keyForceConfirm("y"); cmd == nil {
		t.Error(`"y" did not issue the force rollback`)
	}
}

// An ordinary failure is still an ordinary failure. Only the engine's
// declined-because-edited answer opens the override.
func TestOrdinaryRollbackFailureDoesNotOfferToForce(t *testing.T) {
	m := &appModel{mode: modeHistory, width: 100, height: 24, selected: map[string]bool{},
		checkpoints: []model.Checkpoint{{ID: "cp1", Reversible: true}}}
	m.Update(rolledBackMsg{err: plainErr("checkpoint cp1 has no backed-up files to restore")})
	if m.mode == modeForceConfirm {
		t.Error("a plain failure offered the destructive override")
	}
	if m.mode != modeMessage {
		t.Errorf("mode = %v, want modeMessage", m.mode)
	}
}

type plainErr string

func (e plainErr) Error() string { return string(e) }
