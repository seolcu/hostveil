package core

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// activateEngine registers compose-shaped edits that wait on a recreate, one
// per finding ID, all in one project.
func activateEngine(t *testing.T, runner *restartRunner) (*Engine, []model.Finding) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "stack", "docker-compose.yml")
	reg := fix.NewRegistry()
	build := func(f model.Finding) (fix.Fix, error) {
		return fix.Fix{Label: "edit", Kind: model.RemediationAuto, Actions: []fix.Action{{
			Label: "edit", Benefit: "b", Kind: fix.ActionEdit, CreateIfMissing: true,
			Path:          filepath.Join(dir, f.ID+"-"+f.Service),
			Transform:     func([]byte) ([]byte, error) { return []byte("x\n"), nil },
			TakesEffectOn: "`docker compose up -d " + f.Service + "`",
			Activate:      [][]string{{"docker", "compose", "-f", file, "up", "-d", f.Service}},
		}}}, nil
	}
	reg.Register("compose.a", build)
	reg.Register("compose.b", build)
	e := New(Config{Fixes: reg, Store: history.NewStore(t.TempDir()), Runner: runner})
	var fs []model.Finding
	for _, k := range [][2]string{{"compose.a", "db"}, {"compose.b", "db"}, {"compose.a", "redis"}} {
		fs = append(fs, model.NewFinding(k[0], "t", model.SeverityMedium, model.SourceCompose, model.RemediationAuto, model.WithService(k[1])))
	}
	e.state.replace(model.Report{Findings: fs}, model.Delta{})
	return e, fs
}

// A batch that edited one service twice and another once recreates the
// project once, naming both services, and every fix it covers is in force.
func TestActivateRecreatesEachProjectOnce(t *testing.T) {
	runner := &restartRunner{}
	e, fs := activateEngine(t, runner)
	out := e.ApplyBatch(context.Background(), fs)
	if len(out.Applied) != 3 || len(out.Pending) != 3 {
		t.Fatalf("applied %v pending %v; each edit waits on its recreate", out.Applied, out.Pending)
	}
	plan := e.PendingActivation()
	if plan.Fixes != 3 || len(plan.Commands) != 1 {
		t.Fatalf("plan %+v; want 3 fixes in one command", plan)
	}
	if got := plan.Commands[0][len(plan.Commands[0])-2:]; !slices.Equal(got, []string{"db", "redis"}) {
		t.Errorf("command ends %v, want both services once", got)
	}
	if !slices.Equal(plan.Services, []string{"stack/db", "stack/redis"}) {
		t.Errorf("services %v", plan.Services)
	}
	before := len(runner.calls())
	res := e.Activate(context.Background())
	if res.InForce != 3 || len(res.Failed) != 0 {
		t.Fatalf("activate %+v", res)
	}
	if ran := runner.calls()[before:]; len(ran) != 1 {
		t.Errorf("ran %v, want one recreate", ran)
	}
	cur, _ := e.Current()
	for _, f := range cur.Findings {
		if f.Pending {
			t.Errorf("%s is still pending after its recreate ran", f.Key())
		}
	}
	if p := e.PendingActivation(); p.Fixes != 0 || len(p.Commands) != 0 {
		t.Errorf("nothing is left to activate, got %+v", p)
	}
}

// A recreate that fails leaves its fixes pending, as they were.
func TestAFailedActivationLeavesTheFixesPending(t *testing.T) {
	runner := &restartRunner{}
	e, fs := activateEngine(t, runner)
	e.ApplyBatch(context.Background(), fs)
	runner.mu.Lock()
	runner.failing = true
	runner.mu.Unlock()
	res := e.Activate(context.Background())
	if res.InForce != 0 || len(res.Failed) != 1 {
		t.Fatalf("activate %+v; want the one command failed", res)
	}
	if p := e.PendingActivation(); p.Fixes != 3 {
		t.Errorf("all three are still waiting, got %+v", p)
	}
}

func TestMergeKeepsOtherCommandsAsTheyAre(t *testing.T) {
	merged, byCmd, svcs := mergeActivations(
		[][]string{{"systemctl", "restart", "x"}, {"docker", "compose", "-f", "/s/a/c.yml", "up", "-d", "web"}},
		[]string{"k1", "k2"})
	if len(merged) != 2 || len(byCmd) != 2 || !slices.Equal(svcs, []string{"a/web"}) {
		t.Fatalf("merged %v byCmd %v services %v", merged, byCmd, svcs)
	}
}
