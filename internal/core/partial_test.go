package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// stepRunner fails the nth command it is asked to run, so a multi-command
// exec fix can be stopped part-way.
type stepRunner struct {
	failAt int // 1-based; 0 never fails
	seen   int
}

func (*stepRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (r *stepRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	r.seen++
	if r.seen == r.failAt {
		return nil, errors.New("unit not found")
	}
	return nil, nil
}

// twoStepFix mirrors the shape of the real updates fix: install a package,
// then enable its timer. The first command changes the host.
func twoStepFix() *fix.Registry {
	r := fix.NewRegistry()
	r.Register("updates.testfix", func(model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "Enable unattended upgrades",
			Kind:  model.RemediationReview,
			Actions: []fix.Action{
				{Label: "install and enable", Kind: fix.ActionExec, Commands: [][]string{
					{"apt-get", "install", "-y", "unattended-upgrades"},
					{"systemctl", "enable", "--now", "unattended-upgrades"},
				}},
				{Label: "install only", Kind: fix.ActionExec, Commands: [][]string{
					{"apt-get", "install", "-y", "unattended-upgrades"},
				}},
			},
		}, nil
	})
	return r
}

func execEngine(t *testing.T, r *stepRunner) (*Engine, model.Finding) {
	t.Helper()
	e := New(Config{Fixes: twoStepFix(), Store: history.NewStore(t.TempDir()), Runner: r})
	f := model.NewFinding("updates.testfix", "auto-updates off", model.SeverityWeak,
		model.SourceUpdates, model.RemediationReview)
	return e, f
}

// The first command installs a package; the second fails. Returning before
// the Save left the host changed with no history entry at all, reported only
// as "failed" — so the operator was told nothing happened while a package
// sat newly installed and unnamed.
func TestAPartiallyAppliedExecFixIsRecorded(t *testing.T) {
	e, f := execEngine(t, &stepRunner{failAt: 2})

	_, err := e.ApplyFix(context.Background(), f, 0)
	if err == nil {
		t.Fatal("a fix whose second command failed must report failure")
	}
	if !strings.Contains(err.Error(), "1 of 2") {
		t.Errorf("the error should say how far it got: %v", err)
	}

	cps, listErr := e.ListCheckpoints()
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(cps) != 1 {
		t.Fatalf("want the partial change recorded, got %d checkpoints", len(cps))
	}
	if !strings.Contains(cps[0].Label, "partially applied") {
		t.Errorf("the record should say it is partial, got %q", cps[0].Label)
	}
	// Only what actually ran is recorded — a command that never executed must
	// not appear in the log of what was done to this host.
	if len(cps[0].Commands) != 1 {
		t.Errorf("recorded %d commands, want only the one that ran: %v", len(cps[0].Commands), cps[0].Commands)
	}
}

// Nothing ran, so the host is untouched. A checkpoint here would clutter the
// history with an entry that undoes nothing and describes no change.
func TestAnExecFixThatFailsImmediatelyLeavesNoRecord(t *testing.T) {
	e, f := execEngine(t, &stepRunner{failAt: 1})

	if _, err := e.ApplyFix(context.Background(), f, 0); err == nil {
		t.Fatal("expected failure")
	}
	cps, err := e.ListCheckpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 0 {
		t.Errorf("a fix that changed nothing left %d checkpoint(s)", len(cps))
	}
}

// The ordinary path still records every command and does not call itself
// partial.
func TestAFullyAppliedExecFixIsRecordedWhole(t *testing.T) {
	e, f := execEngine(t, &stepRunner{})

	if _, err := e.ApplyFix(context.Background(), f, 0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cps, err := e.ListCheckpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 1 {
		t.Fatalf("want 1 checkpoint, got %d", len(cps))
	}
	if strings.Contains(cps[0].Label, "partially") {
		t.Errorf("a complete fix must not be labelled partial: %q", cps[0].Label)
	}
	if len(cps[0].Commands) != 2 {
		t.Errorf("recorded %d commands, want both", len(cps[0].Commands))
	}
}
