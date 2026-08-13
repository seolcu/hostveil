package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// A `fix --all` big enough to fill the checkpoint store must still leave every
// fix it applied reversible.
//
// It did not. Pruning runs on every checkpoint save, so a batch that wrote
// more restore points than the store keeps deleted its own earliest ones —
// those fixes were unrollbackable the instant they were applied, and nothing
// told the operator. Two Auto compose rules (no-new-privileges, and a missing
// restart policy) fire on nearly every stock service, so this is a host with
// enough containers, not a pathological one.
//
// The batch size is deliberately not tied to the store's cap: the claim is
// that everything applied stays reversible, whatever the cap happens to be.
func TestALargeBatchLeavesEveryFixRollbackable(t *testing.T) {
	const services = 250

	dir := t.TempDir()
	findings := make([]model.Finding, 0, services)
	for i := range services {
		path := filepath.Join(dir, fmt.Sprintf("compose-%03d.yml", i))
		if err := os.WriteFile(path, []byte("services:\n  app:\n    image: myapp\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		findings = append(findings, model.NewFinding(
			"compose.ds006", "Missing no-new-privileges hardening",
			model.SeverityMedium, model.SourceCompose, model.RemediationAuto,
			model.WithService(fmt.Sprintf("app-%03d", i)),
			model.WithMetadata("file", path),
		))
	}

	r := fix.NewRegistry()
	r.Register("compose.ds006", func(f model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "add no-new-privileges",
			Kind:  model.RemediationAuto,
			Actions: []fix.Action{{
				Label: "harden the service", Kind: fix.ActionEdit,
				Path: f.Metadata["file"],
				Transform: func(in []byte) ([]byte, error) {
					return append(in, []byte("    security_opt:\n      - no-new-privileges:true\n")...), nil
				},
			}},
		}, nil
	})

	store := history.NewStore(t.TempDir())
	e := New(Config{Fixes: r, Store: store})
	e.state.replace(model.Report{Findings: findings}, model.Delta{})

	out := e.ApplyBatch(context.Background(), findings)
	if len(out.Applied) != services {
		t.Fatalf("applied %d of %d fixes (failed: %v)", len(out.Applied), services, out.Failed)
	}

	cps, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != services {
		t.Fatalf("the batch applied %d fixes but left %d restore points — "+
			"%d fixes cannot be undone", services, len(cps), services-len(cps))
	}

	// Not just present: usable. List is newest-first, so the last entry is the
	// batch's first fix — the one pruning destroyed, and the one whose
	// checkpoint has to still restore the file it backed up.
	oldest := cps[len(cps)-1]
	if _, err := e.Rollback(oldest.ID); err != nil {
		t.Fatalf("the batch's first fix does not roll back: %v", err)
	}
	data, err := os.ReadFile(oldest.Files[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "services:\n  app:\n    image: myapp\n" {
		t.Errorf("rollback left the file as %q", data)
	}
}

// A fix that exists and cannot be built is a defect in hostveil, and the
// batch used to report it as Skipped — the same word it uses for "there is no
// fix for this finding". One of those is a fact about the host and the other
// is a bug, and collapsing them is what guarantees nobody looks.
func TestABatchReportsABrokenFixAsFailedNotSkipped(t *testing.T) {
	broken := fix.NewRegistry()
	broken.Register("compose.ds018", func(model.Finding) (fix.Fix, error) {
		return fix.Fix{}, errors.New("finding carries no 'port' evidence")
	})
	e := New(Config{Fixes: broken, Store: history.NewStore(t.TempDir())})

	f := model.NewFinding("compose.ds018", "exposed", model.SeverityHigh, model.SourceCompose,
		model.RemediationAuto, model.WithService("cache"))
	out := e.ApplyBatch(context.Background(), []model.Finding{f})

	if len(out.Skipped) != 0 {
		t.Errorf("a fix that failed to build was reported as skipped: %v", out.Skipped)
	}
	if msg, ok := out.Failed[f.ID]; !ok {
		t.Errorf("Failed does not mention %s: %+v", f.ID, out)
	} else if !strings.Contains(msg, "port") {
		t.Errorf("the failure does not carry the builder's reason: %q", msg)
	}
}
