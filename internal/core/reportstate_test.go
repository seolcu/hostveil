package core

import (
	"sync"
	"testing"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

func stateWith(ids ...string) *reportState {
	var fs []model.Finding
	for _, id := range ids {
		fs = append(fs, model.NewFinding(id, "t", model.SeverityHigh,
			model.SourceSSH, model.RemediationAuto))
	}
	s := &reportState{}
	s.replace(model.Report{Findings: fs}, model.Delta{})
	return s
}

// The invariant this type exists to hold. Report is a struct but Findings
// is a slice, so returning one by value hands the caller the same backing
// array markFixed writes into. That shipped once: the dashboard read the
// findings out of /api/result while a fix marked them, and the race
// detector reported a write in markFixed against json.Encoder.
//
// The race detector found it, which means it needed two goroutines and the
// right interleaving to notice. This asks the question directly.
func TestSnapshotDoesNotAliasTheStoredFindings(t *testing.T) {
	s := stateWith("ssh.rootlogin", "ssh.passwordauth")

	snap, ran := s.snapshot()
	if !ran {
		t.Fatal("snapshot reports no scan has run")
	}

	// Mutating the state must not reach a snapshot already handed out.
	s.markFixed(model.NewFinding("ssh.rootlogin", "t", model.SeverityHigh,
		model.SourceSSH, model.RemediationAuto), false)
	if snap.Findings[0].Fixed {
		t.Error("marking a finding fixed mutated a snapshot taken beforehand — " +
			"the snapshot shares the engine's backing array")
	}

	// And writing through a snapshot must not reach the state.
	snap2, _ := s.snapshot()
	snap2.Findings[1].Fixed = true
	fresh, _ := s.snapshot()
	if fresh.Findings[1].Fixed {
		t.Error("a caller writing to its snapshot changed the engine's own report")
	}
}

func TestSnapshotBeforeAnyScan(t *testing.T) {
	var s reportState
	r, ran := s.snapshot()
	if ran {
		t.Error("hasRun is true before any scan")
	}
	if len(r.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(r.Findings))
	}
}

func TestMarkAndUnmarkFixed(t *testing.T) {
	s := stateWith("ssh.rootlogin", "ssh.passwordauth")
	target := model.NewFinding("ssh.rootlogin", "t", model.SeverityHigh,
		model.SourceSSH, model.RemediationAuto)

	s.markFixed(target, false)
	r, _ := s.snapshot()
	if !r.Findings[0].Fixed || r.Findings[1].Fixed {
		t.Fatalf("markFixed hit the wrong findings: %+v", r.Findings)
	}

	// Matched on the full key where the checkpoint has one.
	unfixed := s.unmarkFixed(history.Checkpoint{FindingKey: target.Key()})
	if len(unfixed) != 1 || unfixed[0] != "ssh.rootlogin" {
		t.Errorf("unmarkFixed returned %v", unfixed)
	}
	r, _ = s.snapshot()
	if r.Findings[0].Fixed {
		t.Error("the finding is still marked fixed after a rollback")
	}
}

// A checkpoint written before FindingKey existed carries only the bare ID.
func TestUnmarkFixedFallsBackToTheBareID(t *testing.T) {
	s := stateWith("ssh.rootlogin")
	s.markFixed(model.NewFinding("ssh.rootlogin", "t", model.SeverityHigh,
		model.SourceSSH, model.RemediationAuto), false)

	if got := s.unmarkFixed(history.Checkpoint{FindingID: "ssh.rootlogin"}); len(got) != 1 {
		t.Errorf("unmarkFixed on a pre-FindingKey checkpoint returned %v", got)
	}
}

// Every exported operation under concurrent use, so the lock discipline is
// exercised rather than assumed. Run under -race this is the guard for the
// failure the type was extracted to make structural.
func TestReportStateIsSafeForConcurrentUse(t *testing.T) {
	s := stateWith("ssh.rootlogin", "ssh.passwordauth", "ssh.x11")
	target := model.NewFinding("ssh.rootlogin", "t", model.SeverityHigh,
		model.SourceSSH, model.RemediationAuto)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(4)
		go func() { defer wg.Done(); _, _ = s.snapshot() }()
		go func() { defer wg.Done(); s.markFixed(target, false) }()
		go func() { defer wg.Done(); _ = s.rescore() }()
		go func() { defer wg.Done(); _ = s.unmarkFixed(history.Checkpoint{FindingKey: target.Key()}) }()
	}
	wg.Wait()
}
