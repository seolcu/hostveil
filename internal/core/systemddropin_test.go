package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func systemdFinding(dropin string) model.Finding {
	return model.NewFinding("systemd.no-new-privileges",
		"A service can gain privileges while running", model.SeverityMedium,
		model.SourceSystemd, model.RemediationReview,
		model.WithService("gitea.service"),
		model.WithMetadata("dropin", dropin))
}

// The drop-in fix through the real engine: preview, apply, roll back.
//
// The whole claim this fix rests on is that creating a file is reversible by
// deleting it, which is what the checker's own instructions already tell the
// operator ("Remove the file to undo it"). That is a claim about the recovery
// layer, so it is worth watching happen rather than reasoning about.
func TestTheSystemdDropInIsWrittenAndCanBeUndone(t *testing.T) {
	dir := t.TempDir()
	dropin := filepath.Join(dir, "gitea.service.d", "50-hostveil.conf")
	f := systemdFinding(dropin)
	e := fixEngine(t)

	// Preview reads a file that is not there and shows what would be created.
	pv, err := e.PreviewFix(f)
	if err != nil {
		t.Fatal(err)
	}
	if pv.Kind != model.RemediationReview {
		t.Errorf("preview kind = %v; the checker asks for Review and the shape must not talk it down", pv.Kind)
	}
	if len(pv.Actions) != 1 || !strings.Contains(pv.Actions[0].Diff, "NoNewPrivileges=yes") {
		t.Fatalf("preview does not show the directive: %+v", pv.Actions)
	}
	if _, err := os.Stat(dropin); !os.IsNotExist(err) {
		t.Fatal("previewing created the file")
	}

	out, err := e.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dropin)
	if err != nil {
		t.Fatalf("the fix reported success and wrote nothing: %v", err)
	}
	if string(got) != "[Service]\nNoNewPrivileges=yes\n" {
		t.Errorf("wrote %q", got)
	}
	if out.CheckpointID == "" {
		t.Fatal("no checkpoint, so nothing to undo with")
	}

	// The re-check cannot see this one: the systemd checker asks systemctl for
	// the effective configuration, and systemd has not re-read the file. So
	// the operator is told what has to happen, and the outcome has to carry
	// the unit for that sentence to be built from. This engine has no checker
	// registered, so the verification itself is exercised on the model below.
	if out.RestartHint != "gitea.service" {
		t.Errorf("RestartHint = %q; without it the note cannot name what to restart", out.RestartHint)
	}
	if msg := model.VerifyStillPresent.Note(out.RestartHint); !strings.Contains(msg, "gitea.service") {
		t.Errorf("the sentence the operator reads does not name the unit: %q", msg)
	}

	if _, err := e.Rollback(out.CheckpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dropin); !os.IsNotExist(err) {
		t.Error("rolling back left the drop-in behind, so the fix is not reversible after all")
	}
}
