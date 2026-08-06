package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// "hostveil wrote the file" and "the finding is gone" are different claims,
// and only the first was ever established: markFixed set Fixed the moment an
// apply returned, and the score moved on that. Action.VerifyCmd (see
// verify_test.go) closes the same gap before a write; this closes the one
// after it.

// stubChecker reports whatever a test tells it to, so the test can say what
// the domain looks like once the fix has landed.
type stubChecker struct {
	src      model.Source
	findings []model.Finding
	state    model.ScanState // zero value runs normally
	reason   string
}

func (c *stubChecker) Source() model.Source { return c.src }

func (c *stubChecker) Available(context.Context, platform.Env) (bool, string) {
	if c.state == model.ScanSkipped {
		return false, c.reason
	}
	return true, ""
}

func (c *stubChecker) Check(context.Context, platform.Env) ([]model.Finding, error) {
	switch c.state {
	case model.ScanError:
		return nil, errors.New(c.reason)
	case model.ScanDegraded:
		return c.findings, &check.PartialError{Reason: c.reason, Covered: 1, Total: 2}
	}
	return c.findings, nil
}

func recheckFinding() model.Finding {
	return model.NewFinding("fileperms.shadow", "World-readable /etc/shadow",
		model.SeverityHigh, model.SourceFilePerms, model.RemediationAuto)
}

// recheckEngine wires one edit fix and one checker that describes the host
// after it, so the apply path is the ordinary one and only the re-check
// varies.
func recheckEngine(t *testing.T, after check.Checker) *Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target.conf")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := fix.NewRegistry()
	r.Register("fileperms.shadow", func(model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "tighten it", Kind: model.RemediationAuto,
			Actions: []fix.Action{{
				Label: "tighten", Kind: fix.ActionEdit, Path: path,
				Transform: func([]byte) ([]byte, error) { return []byte("fixed\n"), nil },
			}},
		}, nil
	})
	e := New(Config{Registry: check.NewRegistry(after), Fixes: r, Store: history.NewStore(t.TempDir())})
	e.state.current = model.Report{Findings: []model.Finding{recheckFinding()}}
	return e
}

func TestApplyConfirmsTheFindingIsGone(t *testing.T) {
	e := recheckEngine(t, &stubChecker{src: model.SourceFilePerms})

	out, err := e.ApplyFix(context.Background(), recheckFinding(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verified != model.VerifyGone {
		t.Errorf("Verified = %v, want gone", out.Verified)
	}
	if out.VerifyMessage == "" {
		t.Error("nothing was said to the operator")
	}
}

// The case that shaped the design. A persisted sysctl drop-in is correct and
// complete, and the running kernel still reports the old value until the next
// boot — so a checker that still sees the finding is not evidence the fix
// failed. Both facts are reported; neither is collapsed into the other.
func TestAStillPresentFindingIsReportedNotTreatedAsFailure(t *testing.T) {
	e := recheckEngine(t, &stubChecker{
		src: model.SourceFilePerms, findings: []model.Finding{recheckFinding()},
	})

	out, err := e.ApplyFix(context.Background(), recheckFinding(), 0)
	if err != nil {
		t.Fatalf("a still-present finding must not fail the apply: %v", err)
	}
	if !out.Success {
		t.Error("the apply reported failure; it succeeded and the finding merely persists")
	}
	if out.Verified != model.VerifyStillPresent {
		t.Errorf("Verified = %v, want still-present", out.Verified)
	}
	if out.CheckpointID == "" {
		t.Error("no checkpoint — the change is real and must stay rollbackable")
	}
	// The Fixed decision is unchanged. Collapsing the two facts would call
	// this fix broken, or call an unverified one confirmed.
	cur, _ := e.Current()
	for _, f := range cur.Findings {
		if f.Key() == recheckFinding().Key() && !f.Fixed {
			t.Error("the finding was un-marked; verification must not change the Fixed decision")
		}
	}
}

// The rule the whole scan is built on, one level down: a re-check that was
// skipped, failed, or covered part of its ground has established nothing.
// "Could not look" is not "still broken", and it is not "fixed" either.
func TestAnUnrunnableRecheckIsUnavailableNotAnAnswer(t *testing.T) {
	for name, state := range map[string]model.ScanState{
		"skipped":  model.ScanSkipped,
		"failed":   model.ScanError,
		"degraded": model.ScanDegraded,
	} {
		t.Run(name, func(t *testing.T) {
			e := recheckEngine(t, &stubChecker{
				src: model.SourceFilePerms, state: state, reason: "docker is unreachable",
			})
			out, err := e.ApplyFix(context.Background(), recheckFinding(), 0)
			if err != nil {
				t.Fatal(err)
			}
			if out.Verified != model.VerifyUnavailable {
				t.Errorf("Verified = %v, want unavailable", out.Verified)
			}
			if out.VerifyNote == "" {
				t.Error("no reason given for the failed re-check")
			}
		})
	}
}

// countingChecker records how often the domain was re-examined.
type countingChecker struct {
	stubChecker
	calls int
}

func (c *countingChecker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	c.calls++
	return c.stubChecker.Check(ctx, env)
}

// A batch re-checks nothing, on purpose. applyFix runs in a loop there, and
// verifying each would re-run a checker once per fix — twenty compose
// findings would mean twenty enumerations of every container on the host.
// A batch ends with the operator rescanning anyway.
func TestBatchDoesNotVerifyEachFix(t *testing.T) {
	c := &countingChecker{stubChecker: stubChecker{src: model.SourceFilePerms}}
	e := recheckEngine(t, c)

	out := e.ApplyBatch(context.Background(), []model.Finding{recheckFinding()})
	if len(out.Applied) != 1 {
		t.Fatalf("batch applied %v, failed %v", out.Applied, out.Failed)
	}
	if c.calls != 0 {
		t.Errorf("the batch re-ran the checker %d time(s); it must not verify per fix", c.calls)
	}
}

// A domain with no registered checker cannot be re-checked, and that is
// "unavailable" rather than a claim in either direction.
func TestVerifyWithNoCheckerForTheDomain(t *testing.T) {
	e := recheckEngine(t, &stubChecker{src: model.SourceSSH}) // a different domain

	out, err := e.ApplyFix(context.Background(), recheckFinding(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verified != model.VerifyUnavailable {
		t.Errorf("Verified = %v, want unavailable", out.Verified)
	}
}

// Every result an interface can receive has to say something, and the
// still-present sentence must not read as a failure — it is most often a
// change that is correct and not yet in force.
func TestEveryVerificationResultHasAMessage(t *testing.T) {
	for _, v := range []model.FixVerification{
		model.VerifyGone, model.VerifyStillPresent, model.VerifyUnavailable,
	} {
		if v.Note("") == "" {
			t.Errorf("%v has no message", v)
		}
	}
	if got := model.VerifyNotRun.Note(""); got != "" {
		t.Errorf("not-run rendered %q; it must say nothing", got)
	}
	// The restart hint is the difference between a useful sentence and a
	// vague one, so it has to reach the text.
	if got := model.VerifyStillPresent.Note("sshd"); !strings.Contains(got, "sshd") {
		t.Errorf("the still-present message drops the restart hint: %q", got)
	}
	// And it must not sound like the fix failed.
	if got := model.VerifyStillPresent.Note(""); strings.Contains(strings.ToLower(got), "failed") {
		t.Errorf("the still-present message reads as a failure: %q", got)
	}
}
