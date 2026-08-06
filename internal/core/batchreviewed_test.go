package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// "Fix everything that needs no human" and "fix everything hostveil can" are
// different requests, and only the first had a command. The classification is
// unchanged by the second: a Review fix is still one that can cut off access
// to the host or has more than one defensible answer. What changes is that
// accepting them no longer means running the tool once per finding.
//
// Both directions are pinned. The plain batch must keep refusing Review — a
// UI that batched them by accident would apply, unattended, exactly the fixes
// that exist because they need a person.
func TestTheReviewedBatchAppliesWhatThePlainOneRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  app:\n    image: myapp\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := fixEngine(t)

	auto := model.NewFinding("compose.ds006", "nnp", model.SeverityMedium, model.SourceCompose,
		model.RemediationAuto, model.WithService("app"), model.WithMetadata("file", path))
	// compose.ds010 is a memory limit: a real fix, and Review because the
	// number is a judgement about the workload.
	review := model.NewFinding("compose.ds010", "no memory limit", model.SeverityLow, model.SourceCompose,
		model.RemediationReview, model.WithService("app"), model.WithMetadata("file", path))
	manual := model.NewFinding("compose.ds001", "priv", model.SeverityHigh, model.SourceCompose,
		model.RemediationManual, model.WithService("app"), model.WithMetadata("file", path))

	plain := engine.ApplyBatch(context.Background(), []model.Finding{auto, review, manual})
	if len(plain.Applied) != 1 || plain.Applied[0] != "compose.ds006" {
		t.Errorf("the plain batch applied %v, want only the Auto fix", plain.Applied)
	}
	if !contains(plain.Skipped, "compose.ds010") {
		t.Errorf("the plain batch did not skip the Review fix: %v", plain.Skipped)
	}

	// Same engine, same findings, with the reviewed ones accepted.
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	reviewed := engine.ApplyBatchWithReviewed(context.Background(), []model.Finding{auto, review, manual})
	if !contains(reviewed.Applied, "compose.ds006") || !contains(reviewed.Applied, "compose.ds010") {
		t.Errorf("the reviewed batch applied %v, want both the Auto and the Review fix", reviewed.Applied)
	}
	if !contains(reviewed.Skipped, "compose.ds001") {
		t.Errorf("the reviewed batch did not skip the Manual finding: %v", reviewed.Skipped)
	}
	after, _ := os.ReadFile(path)
	for _, want := range []string{"no-new-privileges", "mem_limit"} {
		if !strings.Contains(string(after), want) {
			t.Errorf("%q is not in the file the reviewed batch wrote:\n%s", want, after)
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
