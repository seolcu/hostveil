package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/diagnostics"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// crashingRegistry offers one fix whose transform panics, and one builder that
// panics before it can offer anything.
//
// Neither is hypothetical in kind. A Transform is the one place in this
// program where host-supplied bytes meet a hand-written parser — compose YAML
// surgery, JSON5 editing, sshd_config rewriting — and the file it reads is the
// live one, which can have changed since the scan that produced the finding.
func crashingRegistry(t *testing.T) *fix.Registry {
	t.Helper()
	r := fix.NewRegistry()
	r.Register("panic.transform", func(f model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "a fix that crashes while transforming",
			Kind:  model.RemediationAuto,
			Actions: []fix.Action{{
				Kind:    fix.ActionEdit,
				Label:   "rewrite",
				Benefit: "test benefit",
				// The finding's own path, so the transform is reached rather
				// than the read failing first.
				Path: f.Metadata["file"],
				Transform: func([]byte) ([]byte, error) {
					var nothing []int
					_ = nothing[3] // the shape of a real index bug in a parser
					return nil, nil
				},
			}},
		}, nil
	})
	r.Register("panic.build", func(model.Finding) (fix.Fix, error) {
		panic("a builder that crashed while reading the host")
	})
	return r
}

func crashEngine(t *testing.T) *Engine {
	t.Helper()
	return New(Config{Fixes: crashingRegistry(t), Store: history.NewStore(t.TempDir())})
}

func crashFinding(id, path string) model.Finding {
	return model.NewFinding(id, "a finding whose fix crashes", model.SeverityMedium,
		model.SourceCompose, model.RemediationAuto, model.WithMetadata("file", path))
}

// A crash inside a fix must end that fix, not the process.
//
// check.runOne has said since the beginning that a panic in one checker
// degrades only that domain. The fix path had no such rule, and it takes more
// with it: `serve` runs as root and the panic ends the process for every
// request in flight, `fix --all` loses every fix it had not reached, and a TUI
// session dies mid-preview with the terminal still in the alternate screen.
func TestACrashingFixDoesNotTakeTheProcessWithIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.conf")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := crashFinding("panic.transform", path)

	t.Run("preview", func(t *testing.T) {
		_, err := crashEngine(t).PreviewFix(f)
		if err == nil {
			t.Fatal("a fix that panicked previewed successfully")
		}
		if !strings.Contains(err.Error(), "crashed") {
			t.Errorf("the error does not say the fix crashed: %v", err)
		}
	})

	t.Run("apply", func(t *testing.T) {
		_, err := crashEngine(t).ApplyFix(context.Background(), f, 0)
		if err == nil {
			t.Fatal("a fix that panicked applied successfully")
		}
		if !strings.Contains(err.Error(), "crashed") {
			t.Errorf("the error does not say the fix crashed: %v", err)
		}
	})

	// And the file it was pointed at is untouched. A panic partway through a
	// transform must not leave a half-written target — the whole reason apply
	// writes through a temp file and a rename.
	t.Run("the target is untouched", func(t *testing.T) {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "original\n" {
			t.Errorf("the target reads %q, %v — want the original", got, err)
		}
	})
}

// The builder runs before any action exists, so it is a second, earlier place
// a crash can happen — and it reads the host to decide which file to edit.
func TestACrashingBuilderIsAnErrorNotAnExit(t *testing.T) {
	f := crashFinding("panic.build", filepath.Join(t.TempDir(), "x.conf"))
	if _, err := crashEngine(t).PreviewFix(f); err == nil {
		t.Fatal("a builder that panicked previewed successfully")
	}
	if _, err := crashEngine(t).ApplyFix(context.Background(), f, 0); err == nil {
		t.Fatal("a builder that panicked applied successfully")
	}
}

// A panic in a fix must also leave something for `hostveil diagnostics` to
// find afterward, not just an error message on whichever terminal happened
// to be watching. crashError (internal/core/contain.go) is the one place
// that writes it, so this is the same crash the two tests above already
// exercise, read back from disk instead of from the returned error.
func TestACrashingFixLeavesARecordForDiagnostics(t *testing.T) {
	dir := t.TempDir()
	e := New(Config{Fixes: crashingRegistry(t), Store: history.NewStore(dir), Version: "v3-test"})
	f := crashFinding("panic.build", filepath.Join(t.TempDir(), "x.conf"))

	if _, err := e.PreviewFix(f); err == nil {
		t.Fatal("a builder that panicked previewed successfully")
	}

	got, err := diagnostics.Crashes(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d crash records, want 1", len(got))
	}
	if got[0].Version != "v3-test" || got[0].Command != "fix" {
		t.Errorf("crash record does not carry the engine's identity: %+v", got[0])
	}
	if !strings.Contains(got[0].Where, "panic.build") {
		t.Errorf("crash record does not name the finding that crashed: %+v", got[0])
	}
}

// A batch is where this matters most: one crashing fix must not cost the
// operator the rest of the batch.
func TestOneCrashingFixDoesNotAbortTheBatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.conf")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := crashEngine(t)
	out := e.ApplyBatch(context.Background(), []model.Finding{
		crashFinding("panic.transform", path),
		crashFinding("panic.build", path),
	})
	if len(out.Failed) != 2 {
		t.Errorf("batch recorded %d failures, want 2: applied=%v skipped=%v failed=%v",
			len(out.Failed), out.Applied, out.Skipped, out.Failed)
	}
}
