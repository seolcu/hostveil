package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// An edit action could only ever modify a file already on disk, which left
// the whole kernel-hardening domain unfixable: persisting a sysctl value
// means writing a drop-in that by definition is not there — if it were, the
// value would be set and the finding would not have fired.
//
// CreateIfMissing closes that, and the delicate half is not the write but
// the undo. Restoring "this file did not exist" means deleting it, and
// deletion is the one restore operation that cannot be taken back. These
// tests cover the round trip and the two ways it must refuse.

func createFinding() model.Finding {
	return model.NewFinding("sysctl.kptr-restrict", "Kernel pointers are visible",
		model.SeverityLow, model.SourceSysctl, model.RemediationReview,
		model.WithEvidence("set", "kernel.kptr_restrict=1"))
}

// createEngine wires an engine whose one fix creates path.
func createEngine(t *testing.T, path string) *Engine {
	t.Helper()
	r := fix.NewRegistry()
	r.Register("sysctl.kptr-restrict", func(model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "create it",
			Kind:  model.RemediationReview,
			Actions: []fix.Action{
				{
					Label: "write the drop-in", Kind: fix.ActionEdit,
					Path: path, CreateIfMissing: true,
					Transform: func(in []byte) ([]byte, error) {
						return append(in, []byte("kernel.kptr_restrict = 1\n")...), nil
					},
				},
				{Label: "apply now", Kind: fix.ActionExec, Commands: [][]string{{"true"}}},
			},
		}, nil
	})
	return New(Config{Fixes: r, Store: history.NewStore(t.TempDir())})
}

// The whole point: a fix creates a file that was not there, and rolling it
// back leaves the host as it found it — no file, not an empty one. An empty
// drop-in would look configured while configuring nothing.
func TestCreateThenRollbackRemovesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "60-hostveil-kptr.conf")
	e := createEngine(t, path)
	e.current = model.Report{Findings: []model.Finding{createFinding()}}

	out, err := e.ApplyFix(context.Background(), createFinding(), 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !out.Success || out.CheckpointID == "" {
		t.Fatalf("apply produced no checkpoint: %+v", out)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the fix did not create the file: %v", err)
	}
	if !strings.Contains(string(body), "kernel.kptr_restrict = 1") {
		t.Errorf("created file has the wrong contents:\n%s", body)
	}

	if _, err := e.Rollback(out.CheckpointID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		rest, _ := os.ReadFile(path)
		t.Errorf("rollback left the file behind (%v):\n%s", err, rest)
	}
}

// The diff an operator approves must show the whole file as an addition.
// A preview that rendered nothing — or that failed because the target is
// absent — would ask them to approve a change they cannot see.
func TestPreviewOfACreatedFileShowsTheWholeBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "60-hostveil-kptr.conf")
	e := createEngine(t, path)

	p, err := e.PreviewFix(createFinding())
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(p.Actions) == 0 {
		t.Fatal("preview has no actions")
	}
	if !strings.Contains(p.Actions[0].Diff, "+kernel.kptr_restrict = 1") {
		t.Errorf("the diff does not show the created line:\n%s", p.Actions[0].Diff)
	}
	// Preview is pure. It must not have brought the file into existence.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("preview created the file; it must only ever compute a diff")
	}
}

// Rollback deletes, and deletion cannot be undone — so the external-edit
// guard matters more here than anywhere else. An operator who tuned the
// drop-in hostveil created must not have it removed out from under them by
// a rollback that thinks it is restoring an absence.
func TestRollbackDeclinesToDeleteAnEditedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "60-hostveil-kptr.conf")
	e := createEngine(t, path)
	e.current = model.Report{Findings: []model.Finding{createFinding()}}

	out, err := e.ApplyFix(context.Background(), createFinding(), 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := os.WriteFile(path, []byte("kernel.kptr_restrict = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = e.Rollback(out.CheckpointID)
	if !IsExternalEdit(err) {
		t.Fatalf("rollback err = %v, want an external-edit refusal", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the declined rollback deleted the file anyway: %v", err)
	}
}

// Deleting a file that is already gone is the desired end state, not a
// failure. An operator who removed the drop-in by hand and then rolled back
// should get success, not an error describing what they already did.
func TestRollbackOfAnAlreadyDeletedFileSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "60-hostveil-kptr.conf")
	e := createEngine(t, path)
	e.current = model.Report{Findings: []model.Finding{createFinding()}}

	out, err := e.ApplyFix(context.Background(), createFinding(), 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Rollback(out.CheckpointID); err != nil {
		t.Errorf("rollback of an already-absent file failed: %v", err)
	}
}

// CreateIfMissing is opt-in per action for a reason: for every other fix a
// missing target is a real error. An sshd_config that is not there means
// the finding was stale or the path was wrong, and quietly creating one
// would be worse than failing.
func TestEditWithoutCreateStillFailsOnAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.conf")
	r := fix.NewRegistry()
	r.Register("sysctl.kptr-restrict", func(model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "edit it", Kind: model.RemediationAuto,
			Actions: []fix.Action{{
				Label: "edit", Kind: fix.ActionEdit, Path: path,
				Transform: func(in []byte) ([]byte, error) { return in, nil },
			}},
		}, nil
	})
	e := New(Config{Fixes: r, Store: history.NewStore(t.TempDir())})
	e.current = model.Report{Findings: []model.Finding{createFinding()}}

	if _, err := e.ApplyFix(context.Background(), createFinding(), 0); err == nil {
		t.Error("applying an edit to a missing file succeeded; only CreateIfMissing may do that")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the failed edit created the file")
	}
}
