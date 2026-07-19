package check

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// stubChecker scripts one checker's outcome so the orchestrator's state
// mapping can be tested without any real host access.
type stubChecker struct {
	src       model.Source
	available bool
	reason    string
	findings  []model.Finding
	err       error
	panics    bool
}

func (s stubChecker) Source() model.Source { return s.src }

func (s stubChecker) Available(context.Context, platform.Env) (bool, string) {
	return s.available, s.reason
}

func (s stubChecker) Check(context.Context, platform.Env) ([]model.Finding, error) {
	if s.panics {
		panic("boom")
	}
	return s.findings, s.err
}

func oneFinding() []model.Finding {
	return []model.Finding{model.NewFinding(
		"cve.CVE-2024-0001", "vulnerable package", model.SeverityHigh,
		model.SourceCVE, model.RemediationManual)}
}

func runStub(t *testing.T, c Checker) Result {
	t.Helper()
	results := NewRegistry(c).Run(context.Background(), platform.Env{}, nil)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	return results[0]
}

// The point of PartialError: the domain ran and found something real, but
// covered only part of its ground. Both halves matter — the Degraded state so
// the score can be flagged, and the findings so partial evidence isn't thrown
// away.
func TestPartialErrorBecomesDegradedAndKeepsFindings(t *testing.T) {
	res := runStub(t, stubChecker{
		src:       model.SourceCVE,
		available: true,
		findings:  oneFinding(),
		err:       &PartialError{Reason: "some images were unreadable", Covered: 3, Total: 9},
	})

	if res.State != model.ScanDegraded {
		t.Errorf("got state %v, want ScanDegraded", res.State)
	}
	if len(res.Findings) != 1 {
		t.Errorf("degraded result dropped its findings: %d kept", len(res.Findings))
	}
	if res.Reason == "" {
		t.Error("degraded result must carry a reason")
	}
}

// The fraction belongs in the reason so each checker doesn't hand-format it.
func TestPartialErrorReasonIncludesCoverage(t *testing.T) {
	got := (&PartialError{Reason: "some images were unreadable", Covered: 3, Total: 9}).Error()
	if want := "some images were unreadable (covered 3 of 9)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// With no total to report, the reason stands alone.
	if got := (&PartialError{Reason: "cannot read firewall state"}).Error(); got != "cannot read firewall state" {
		t.Errorf("got %q", got)
	}
}

// A PartialError reached through a wrapping chain must still be recognized —
// checkers naturally wrap errors on the way out.
func TestWrappedPartialErrorStillDegrades(t *testing.T) {
	err := fmt.Errorf("scan images: %w", &PartialError{Reason: "partial", Covered: 1, Total: 2})
	res := runStub(t, stubChecker{src: model.SourceCVE, available: true, findings: oneFinding(), err: err})
	if res.State != model.ScanDegraded {
		t.Errorf("got state %v, want ScanDegraded", res.State)
	}
}

// The PartialError check runs before the plain-error branch; an ordinary
// failure must not be softened into Degraded, because Degraded is still scored
// and Error is not.
func TestOrdinaryErrorStaysError(t *testing.T) {
	res := runStub(t, stubChecker{
		src:       model.SourceCVE,
		available: true,
		err:       errors.New("no image could be scanned"),
	})
	if res.State != model.ScanError {
		t.Errorf("got state %v, want ScanError", res.State)
	}
	if res.State.Ran() {
		t.Error("an errored domain must not count as having run")
	}
}

// Degraded counts as having run, so its axis is scored rather than excluded.
// This is the contract ScoreReport relies on to flag rather than drop it.
func TestDegradedCountsAsRan(t *testing.T) {
	if !model.ScanDegraded.Ran() {
		t.Error("ScanDegraded must count as having run")
	}
}

// The pre-existing guarantees, pinned here because this package had no test
// file: an absent dependency is a clean skip, and a panic degrades only its
// own domain.
func TestUnavailableIsSkippedNotError(t *testing.T) {
	res := runStub(t, stubChecker{src: model.SourceCVE, available: false, reason: "Trivy not installed"})
	if res.State != model.ScanSkipped {
		t.Errorf("got state %v, want ScanSkipped", res.State)
	}
	if res.Reason != "Trivy not installed" {
		t.Errorf("got reason %q", res.Reason)
	}
}

func TestPanicIsContainedAsError(t *testing.T) {
	results := NewRegistry(
		stubChecker{src: model.SourceCVE, available: true, panics: true},
		stubChecker{src: model.SourceCompose, available: true, findings: oneFinding()},
	).Run(context.Background(), platform.Env{}, nil)

	if results[0].State != model.ScanError {
		t.Errorf("panicking checker: got %v, want ScanError", results[0].State)
	}
	if results[1].State != model.ScanDone || len(results[1].Findings) != 1 {
		t.Error("a panic in one checker must not affect the others")
	}
}
