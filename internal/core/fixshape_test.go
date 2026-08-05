package core

import (
	"context"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// fix.Validate is the shape contract, and for most of this project's life it
// ran only in internal/fix/fix_test.go — against the representative findings
// that file happens to construct. A registration that came out malformed for
// any other finding was reported by nothing.
//
// It was not a quiet failure either. classify saw a fixable Kind, left the
// finding Auto, and a UI drew a fix button; the first thing to notice was
// applyEdit calling a nil Transform, and there is no recover on that path.
//
// These tests build fixes that are broken in each of the ways Validate
// knows about and require the engine to demote rather than offer.

type shapeChecker struct{ findings []model.Finding }

func (c *shapeChecker) Source() model.Source { return model.SourceSysctl }

func (c *shapeChecker) Available(context.Context, platform.Env) (bool, string) { return true, "" }

func (c *shapeChecker) Check(context.Context, platform.Env) ([]model.Finding, error) {
	return c.findings, nil
}

func shapeFinding() model.Finding {
	return model.NewFinding("sysctl.aslr", "ASLR disabled", model.SeverityExposed,
		model.SourceSysctl, model.RemediationAuto)
}

// shapeEngine wires one checker emitting one Auto finding, and one fix
// registration returning fx.
func shapeEngine(t *testing.T, fx fix.Fix) *Engine {
	t.Helper()
	r := fix.NewRegistry()
	r.Register("sysctl.aslr", func(model.Finding) (fix.Fix, error) { return fx, nil })
	return New(Config{
		Registry: check.NewRegistry(&shapeChecker{findings: []model.Finding{shapeFinding()}}),
		Fixes:    r,
		Store:    history.NewStore(t.TempDir()),
	})
}

func TestMalformedFixIsDemotedNotOffered(t *testing.T) {
	for name, broken := range map[string]fix.Fix{
		// The one that panics: applyEdit and previewEdit both call
		// a.Transform with no nil check.
		"edit with no Transform": {
			Label: "x", Kind: model.RemediationAuto,
			Actions: []fix.Action{{Label: "x", Kind: fix.ActionEdit, Path: "/tmp/x"}},
		},
		"exec with no command": {
			Label: "x", Kind: model.RemediationAuto,
			Actions: []fix.Action{{Label: "x", Kind: fix.ActionExec}},
		},
		// Auto is a claim about shape — one mechanical action. Two of them
		// is a Review wearing Auto's label, and ApplyBatch silently skips it
		// while every interface counts it as one that will be applied.
		"auto with two actions": {
			Label: "x", Kind: model.RemediationAuto,
			Actions: []fix.Action{
				{Label: "a", Kind: fix.ActionEdit, Path: "/tmp/a", Transform: func(b []byte) ([]byte, error) { return b, nil }},
				{Label: "b", Kind: fix.ActionEdit, Path: "/tmp/b", Transform: func(b []byte) ([]byte, error) { return b, nil }},
			},
		},
		"review with one action": {
			Label: "x", Kind: model.RemediationReview,
			Actions: []fix.Action{
				{Label: "a", Kind: fix.ActionEdit, Path: "/tmp/a", Transform: func(b []byte) ([]byte, error) { return b, nil }},
			},
		},
		"mode change with no Mode function": {
			Label: "x", Kind: model.RemediationAuto,
			Actions: []fix.Action{{Label: "x", Kind: fix.ActionMode, Paths: []string{"/tmp/x"}}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := shapeEngine(t, broken)
			r := e.Scan(context.Background(), nil)
			if len(r.Findings) != 1 {
				t.Fatalf("expected the one finding, got %d", len(r.Findings))
			}

			// Demoted, which is the same answer an unregistered fix gets.
			if got := r.Findings[0].Remediation; got != model.RemediationManual {
				t.Errorf("remediation = %v, want Manual — a fix whose shape contradicts its kind "+
					"must not reach a UI as a button", got)
			}
			if r.Findings[0].IsFixable() {
				t.Error("a malformed fix must not present the finding as fixable")
			}

			// And the direct route refuses in words rather than panicking.
			if _, err := e.PreviewFix(shapeFinding()); err == nil {
				t.Error("PreviewFix accepted a malformed fix")
			}
		})
	}
}

// The counterpart: a well-formed fix must still be offered, or the guard
// above would "pass" by rejecting everything.
func TestWellFormedFixIsStillOffered(t *testing.T) {
	e := shapeEngine(t, fix.Fix{
		Label: "tighten it", Kind: model.RemediationAuto,
		Actions: []fix.Action{{
			Label: "tighten", Kind: fix.ActionEdit, Path: "/tmp/ok",
			Transform: func(b []byte) ([]byte, error) { return b, nil },
		}},
	})
	r := e.Scan(context.Background(), nil)
	if len(r.Findings) != 1 {
		t.Fatalf("expected the one finding, got %d", len(r.Findings))
	}
	if got := r.Findings[0].Remediation; got != model.RemediationAuto {
		t.Errorf("remediation = %v, want Auto", got)
	}
}

// The message has to name the fix that is broken. A registry bug that says
// only "invalid" leaves a maintainer diffing registrations.
func TestMalformedFixErrorNamesTheFinding(t *testing.T) {
	e := shapeEngine(t, fix.Fix{
		Label: "x", Kind: model.RemediationAuto,
		Actions: []fix.Action{{Label: "x", Kind: fix.ActionEdit, Path: "/tmp/x"}},
	})
	_, err := e.PreviewFix(shapeFinding())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "sysctl.aslr") {
		t.Errorf("error %q does not name the finding whose fix is malformed", err)
	}
}
