package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// restartRunner records every command and fails the restart while failing is
// set, which is how a daemon that will not start under a new config looks to
// the engine.
type restartRunner struct {
	mu      sync.Mutex
	ran     []string
	failing bool
}

func (r *restartRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cmd := strings.Join(append([]string{name}, args...), " ")
	r.ran = append(r.ran, cmd)
	if r.failing {
		return nil, errors.New("Job for docker.service failed")
	}
	return nil, nil
}

func (r *restartRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (r *restartRunner) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.ran)
}

func afterWriteEngine(t *testing.T, path string, runner *restartRunner) (*Engine, model.Finding) {
	t.Helper()
	reg := fix.NewRegistry()
	reg.Register("dockerd.test", func(model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "set a daemon default",
			Kind:  model.RemediationReview,
			Actions: []fix.Action{{
				Label: "set it and restart", Benefit: "b", Warning: "restarts docker",
				Kind: fix.ActionEdit, Path: path,
				Transform:  func([]byte) ([]byte, error) { return []byte("new\n"), nil },
				AfterWrite: [][]string{{"systemctl", "restart", "docker"}},
			}},
		}, nil
	})
	e := New(Config{Fixes: reg, Store: history.NewStore(t.TempDir()), Runner: runner})
	f := model.NewFinding("dockerd.test", "t", model.SeverityLow, model.SourceDockerd, model.RemediationReview)
	return e, f
}

func TestAfterWriteRunsOnceTheEditIsWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &restartRunner{}
	e, f := afterWriteEngine(t, path, runner)

	out, err := e.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new\n" {
		t.Errorf("file = %q, want the edit", got)
	}
	if !slices.Equal(runner.calls(), []string{"systemctl restart docker"}) {
		t.Errorf("ran %v, want one restart after the write", runner.calls())
	}

	// Rolling back puts the old file in force the same way.
	if _, err := e.Rollback(out.CheckpointID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old\n" {
		t.Errorf("after rollback file = %q, want the original", got)
	}
	if n := len(runner.calls()); n != 2 {
		t.Errorf("ran %v; the rollback must restart under the restored file", runner.calls())
	}
}

// The case AfterWrite exists to survive: the daemon refuses the new file.
// Leaving it there leaves the daemon down, so the original goes back and the
// restart runs again under it, and nothing is left in history claiming a
// change that is no longer on the host.
func TestAFailedRestartPutsTheOriginalBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &restartRunner{failing: true}
	e, f := afterWriteEngine(t, path, runner)

	_, err := e.ApplyFix(context.Background(), f, 0)
	if err == nil {
		t.Fatal("a failed restart must fail the fix")
	}
	if got, _ := os.ReadFile(path); string(got) != "old\n" {
		t.Errorf("file = %q; the original must be restored when the restart fails", got)
	}
	if n := len(runner.calls()); n != 2 {
		t.Errorf("ran %v; the restart must be retried under the restored file", runner.calls())
	}
	if !strings.Contains(err.Error(), "may be down") {
		t.Errorf("both restarts failed, and the error must say the service may be down: %v", err)
	}
	cps, _ := e.ListCheckpoints()
	if len(cps) != 0 {
		t.Errorf("history holds %d checkpoints for a change that was undone", len(cps))
	}
}

// When only the new file is the problem, the second restart succeeds and the
// error says nothing changed.
func TestARestartThatFailsOnlyUnderTheEditReportsNothingChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &flakyRestart{}
	reg := fix.NewRegistry()
	reg.Register("dockerd.test", func(model.Finding) (fix.Fix, error) {
		return fix.Fix{Label: "x", Kind: model.RemediationReview, Actions: []fix.Action{{
			Label: "x", Benefit: "b", Warning: "w", Kind: fix.ActionEdit, Path: path,
			Transform:  func([]byte) ([]byte, error) { return []byte("new\n"), nil },
			AfterWrite: [][]string{{"systemctl", "restart", "docker"}},
		}}}, nil
	})
	e := New(Config{Fixes: reg, Store: history.NewStore(t.TempDir()), Runner: runner})
	f := model.NewFinding("dockerd.test", "t", model.SeverityLow, model.SourceDockerd, model.RemediationReview)

	_, err := e.ApplyFix(context.Background(), f, 0)
	if err == nil || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("err = %v, want one saying nothing changed", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old\n" {
		t.Errorf("file = %q, want the original", got)
	}
}

// flakyRestart fails while the file holds the edit and succeeds otherwise.
type flakyRestart struct{ n int }

func (r *flakyRestart) Run(context.Context, string, ...string) ([]byte, error) {
	r.n++
	if r.n == 1 {
		return nil, errors.New("daemon refused the configuration")
	}
	return nil, nil
}

func (r *flakyRestart) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

// The preview shows what will run after the write, so the restart is not a
// surprise the diff did not mention.
func TestThePreviewShowsWhatRunsAfterTheWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, f := afterWriteEngine(t, path, &restartRunner{})
	p, err := e.PreviewFix(f)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Actions[0].Commands; len(got) != 1 || strings.Join(got[0], " ") != "systemctl restart docker" {
		t.Errorf("preview commands = %v", got)
	}
}
