package core

import (
	"context"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// Nothing that runs a command may end up Auto.
//
// "Auto means safe to apply unattended" rests on the fix being reversible,
// and an exec action writes no checkpoint — `fix --all` would run it as root
// with no way to undo it through hostveil. register.go states the rule five
// times over ("`apt upgrade` is exec, so never Auto"; "Being exec, it is
// Review and can never be Auto"), and every checker upholds it by hand: the
// updates domain declares updates.disabled Review while its registered fix is
// shaped Auto, and classify taking the stricter of the two is the only thing
// standing between `fix --all` and `apt-get install`.
//
// That is a convention, not a guard. One checker declaring Auto for a finding
// whose fix happens to be exec is all it takes, and the failure is silent: a
// package installed and a service enabled on the operator's host, unattended,
// with no checkpoint and no rollback.
func TestAnExecFixIsNeverClassifiedAuto(t *testing.T) {
	r := fix.NewRegistry()
	r.Register("updates.disabled", func(model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "Enable automatic security updates",
			Kind:  model.RemediationAuto, // one action: Auto *shape*
			Actions: []fix.Action{{
				Label:    "Install and enable unattended-upgrades",
				Kind:     fix.ActionExec,
				Commands: [][]string{{"apt-get", "install", "-y", "unattended-upgrades"}},
			}},
		}, nil
	})
	e := New(Config{Fixes: r, Store: history.NewStore(t.TempDir())})

	// A checker that declares Auto — which nothing in-tree does today, and
	// which nothing stops.
	findings := []model.Finding{model.NewFinding(
		"updates.disabled", "Automatic security updates are not enabled",
		model.SeverityWeak, model.SourceUpdates, model.RemediationAuto)}

	e.classify(findings)

	if findings[0].Remediation == model.RemediationAuto {
		t.Fatal("a fix that runs a command was classified Auto — `fix --all` " +
			"would execute it unattended, as root, with no checkpoint to undo it")
	}
	if !findings[0].Remediation.IsFixable() {
		t.Errorf("the fix was demoted past Review to %v; it is still applicable "+
			"with a human approving it", findings[0].Remediation)
	}

	// And the batch must actually decline it, which is the consequence that
	// matters rather than the label.
	out := e.ApplyBatch(context.Background(), findings)
	if len(out.Applied) != 0 {
		t.Errorf("`fix --all` applied an exec fix: %v", out.Applied)
	}
}
