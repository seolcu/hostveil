package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// ApplyOne exists so the web dashboard's per-item progress modal can drive a
// real loop over eligible findings without paying for ApplyFix's verify step
// once per item (see ApplyFix's and ApplyOne's doc comments). These pin that
// it offers exactly ApplyBatch's own eligibility rule and no-verify
// semantics — not a third set of rules a batch and a per-item loop could
// silently disagree on.
func TestApplyOneAppliesAnEligibleAutoFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  app:\n    image: myapp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := fixEngine(t)
	f := model.NewFinding("compose.ds006", "nnp", model.SeverityMedium, model.SourceCompose,
		model.RemediationAuto, model.WithService("app"), model.WithMetadata("file", path))

	out, eligible, err := engine.ApplyOne(context.Background(), f, false)
	if err != nil {
		t.Fatalf("ApplyOne: %v", err)
	}
	if !eligible {
		t.Fatal("an unfixed Auto finding was reported ineligible")
	}
	if !out.Success {
		t.Errorf("outcome.Success = false, want true")
	}
	// The whole reason this exists rather than a loop over ApplyFix: no
	// verify step ran, so there is nothing in Verified/VerifyMessage.
	if out.Verified != model.VerifyNotRun || out.VerifyMessage != "" {
		t.Errorf("ApplyOne ran a verify step (Verified=%v, VerifyMessage=%q); "+
			"that is ApplyFix's job, and doing it here defeats the point of a "+
			"per-item loop that must not re-run a domain checker per finding",
			out.Verified, out.VerifyMessage)
	}
}

// A finding hostveil has already applied is reported ineligible (skipped),
// not failed — re-applying it on every tick of a progress loop would write
// a new checkpoint over a file that has not changed since the last one.
func TestApplyOneSkipsAnAlreadyFixedFinding(t *testing.T) {
	engine := fixEngine(t)
	f := model.NewFinding("compose.ds006", "nnp", model.SeverityMedium, model.SourceCompose,
		model.RemediationAuto, model.WithService("app"))
	f.Fixed = true

	out, eligible, err := engine.ApplyOne(context.Background(), f, false)
	if err != nil {
		t.Fatalf("ApplyOne: %v", err)
	}
	if eligible {
		t.Error("an already-fixed finding was reported eligible")
	}
	if out.Success {
		t.Error("an already-fixed finding was reported applied")
	}
}

// A Manual finding is never eligible, reviewed or not — there is no
// mechanical remediation for a per-item loop to run.
func TestApplyOneSkipsManual(t *testing.T) {
	engine := fixEngine(t)
	f := model.NewFinding("compose.ds001", "priv", model.SeverityHigh, model.SourceCompose,
		model.RemediationManual, model.WithService("app"))

	if _, eligible, err := engine.ApplyOne(context.Background(), f, false); err != nil || eligible {
		t.Errorf("ApplyOne(reviewed=false) on a Manual finding: eligible=%v err=%v, want false, nil", eligible, err)
	}
	if _, eligible, err := engine.ApplyOne(context.Background(), f, true); err != nil || eligible {
		t.Errorf("ApplyOne(reviewed=true) on a Manual finding: eligible=%v err=%v, want false, nil", eligible, err)
	}
}

// A Review finding is skipped by the plain (unreviewed) loop and applied,
// through its first alternative, by the reviewed one — the same distinction
// ApplyBatch/ApplyBatchWithReviewed make, since ApplyOne is that same
// per-item decision exposed as a single call.
func TestApplyOneReviewFindingNeedsReviewedFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  app:\n    image: myapp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := fixEngine(t)
	f := model.NewFinding("compose.ds010", "no memory limit", model.SeverityLow, model.SourceCompose,
		model.RemediationReview, model.WithService("app"), model.WithMetadata("file", path))

	if _, eligible, err := engine.ApplyOne(context.Background(), f, false); err != nil || eligible {
		t.Errorf("ApplyOne(reviewed=false) on a Review finding: eligible=%v err=%v, want false, nil", eligible, err)
	}

	out, eligible, err := engine.ApplyOne(context.Background(), f, true)
	if err != nil {
		t.Fatalf("ApplyOne(reviewed=true): %v", err)
	}
	if !eligible || !out.Success {
		t.Errorf("ApplyOne(reviewed=true) on a Review finding: eligible=%v success=%v, want true, true", eligible, out.Success)
	}
}
