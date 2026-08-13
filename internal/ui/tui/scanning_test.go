package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// scanningModel is a scan part way through: a plan, some domains finished,
// one still working and one that never started.
func scanningModel(w, h int) *appModel {
	m := &appModel{mode: modeScanning, width: w, height: h, selected: map[string]bool{},
		status: "Scanning…"}
	m.scanPlan = []model.Source{
		model.SourceSSH, model.SourceFirewall, model.SourcePorts,
		model.SourceCompose, model.SourceCVE, model.SourceAgent,
	}
	m.scanState = map[model.Source]model.ScanState{}
	for _, ev := range []model.ScanEvent{
		{Source: model.SourceSSH, State: model.ScanRunning},
		{Source: model.SourceSSH, State: model.ScanDone},
		{Source: model.SourceFirewall, State: model.ScanRunning},
		{Source: model.SourceFirewall, State: model.ScanDone},
		{Source: model.SourcePorts, State: model.ScanRunning},
		{Source: model.SourcePorts, State: model.ScanDegraded},
		{Source: model.SourceCVE, State: model.ScanRunning},
	} {
		m.noteScanEvent(ev)
	}
	m.scanElapsed = 92 * time.Second
	return m
}

// The screen's whole job is to answer two questions an operator has while
// waiting, and neither of them could be answered from the event stream alone.
//
// "How far in?" needs a denominator. A checker announces itself when it starts
// and again when it finishes, so a reader can count what has happened and
// never what is left — the count came from the engine's plan.
//
// "Is it hung, and on what?" needs the domain still working to be named. On a
// real host the answer is almost always the CVE scan, which shells out to
// Trivy and can take minutes.
func TestTheScanScreenAnswersHowFarInAndOnWhat(t *testing.T) {
	got := plain(scanningModel(96, 34).View().Content)

	for _, want := range []string{
		"3 of 6",    // the denominator, which only the plan can supply
		"1:32",      // elapsed, so a long wait is visibly a wait
		"scanning…", // and something is still working
		"partial",   // a degraded domain is not reported as done
		"waiting",   // a domain that has not started is on the screen already
		"Container", // ...by name, before it has said anything itself
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the scanning screen does not show %q:\n%s", want, got)
		}
	}
}

// Every domain the scan will run has a row from the first frame.
//
// Drawing only the domains that have reported would make the list grow as the
// scan proceeds, which is a worse answer to "is this hung" than no list: the
// screen would keep changing while the one slow domain sat there, and the
// domains still queued — the ones the operator is waiting for — would be the
// ones not shown.
func TestEveryPlannedDomainHasARowBeforeItStarts(t *testing.T) {
	m := scanningModel(96, 34)
	got := plain(m.View().Content)
	for _, src := range m.scanPlan {
		if !strings.Contains(got, src.Label()) {
			t.Errorf("%s is in the plan and not on the screen", src.Label())
		}
	}
}

// No estimate of the time remaining, deliberately.
//
// Eleven of the twelve domains together finish inside a second; the twelfth
// shells out to Trivy, whose duration depends on the images on the host, their
// size, and whether the vulnerability database has to be downloaded first.
// Nearly the whole of the unknown sits in the one domain nothing can predict,
// so a figure would be confidently wrong for most of the wait — the same
// reason a skipped domain is scored N/A rather than 100.
//
// Pinned because it is a decision, and a decision nobody wrote down is one the
// next person re-litigates by adding the feature.
func TestTheScanScreenDoesNotEstimateWhatItCannotKnow(t *testing.T) {
	got := strings.ToLower(plain(scanningModel(96, 34).View().Content))
	for _, phrase := range []string{"remaining", "eta", "left", "estimate", "about "} {
		if strings.Contains(got, phrase) {
			t.Errorf("the scanning screen says %q; the CVE domain's duration is not predictable and the figure would be wrong for most of the wait", phrase)
		}
	}
}

// View must be a pure function of the model, so the elapsed figure is stored
// by the ticker and never read from the clock while rendering.
//
// A clock read inside View would make two renders of one state differ, which
// is the property TestScanProgressIsStablyOrdered holds for the status line —
// and the reason that test exists is that a screen redrawing differently for
// no reason is indistinguishable from one redrawing because something changed.
func TestTheScanScreenReadsTheClockThroughTheModel(t *testing.T) {
	m := scanningModel(96, 34)
	first := m.View().Content
	time.Sleep(2 * time.Millisecond)
	if second := m.View().Content; first != second {
		t.Error("two renders of one model differ, so something in the scanning screen is reading the clock rather than the model")
	}

	// And the ticker is what moves it.
	before := m.scanElapsed
	m.scanStartedAt = time.Now().Add(-5 * time.Second)
	next, _ := m.Update(scanTickMsg{})
	if got := next.(*appModel).scanElapsed; got == before || got < 5*time.Second {
		t.Errorf("scanElapsed = %v after a tick, want at least 5s", got)
	}
}

// The clock stops with the screen. A tick that kept re-arming after the scan
// finished would redraw the findings list once a second for as long as the
// program ran.
func TestTheScanClockStopsWhenTheScanDoes(t *testing.T) {
	m := scanningModel(96, 34)
	m.mode = modeList
	if _, cmd := m.Update(scanTickMsg{}); cmd != nil {
		t.Error("the ticker re-armed after the scan finished")
	}
}

// With no engine to ask there is no plan, and the screen falls back to what it
// drew before rather than to nothing. Every model built as a bare struct
// literal in this package is in that state.
func TestTheScanScreenStillRendersWithNoPlan(t *testing.T) {
	m := &appModel{mode: modeScanning, width: 96, height: 34, selected: map[string]bool{},
		status: "Scanning…"}
	if got := plain(m.View().Content); !strings.Contains(got, "Scanning…") {
		t.Errorf("a scan with no plan renders nothing:\n%s", got)
	}
	m.noteScanEvent(model.ScanEvent{Source: model.SourceSSH, State: model.ScanRunning})
	if got := plain(m.View().Content); !strings.Contains(got, model.SourceSSH.Label()) {
		t.Errorf("a domain that reported is not on the screen:\n%s", got)
	}
}
