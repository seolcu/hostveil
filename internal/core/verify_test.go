package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// verifyRunner stands in for a config validator. accept decides the verdict
// for the contents of the file it is pointed at, so a test can make the
// checker approve the original and reject the replacement — or reject both,
// which is what a validator that cannot run on this host looks like.
type verifyRunner struct {
	absent bool
	accept func(content string) bool
	calls  int
}

func (r *verifyRunner) LookPath(name string) (string, error) {
	if r.absent {
		return "", errors.New("not found: " + name)
	}
	return "/usr/sbin/" + name, nil
}

func (r *verifyRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls++
	if len(args) == 0 {
		return nil, errors.New("no file to check")
	}
	data, err := os.ReadFile(args[len(args)-1])
	if err != nil {
		return nil, err
	}
	if r.accept(string(data)) {
		return nil, nil
	}
	return nil, errors.New("bad configuration file")
}

// verifiedFix registers one edit fix whose Transform appends marker and
// which validates through the runner.
func verifiedFix(marker string) *fix.Registry {
	r := fix.NewRegistry()
	r.Register("ssh.testfix", func(f model.Finding) (fix.Fix, error) {
		return fix.Fix{
			Label: "test fix",
			Kind:  model.RemediationAuto,
			Actions: []fix.Action{{
				Label:   "test fix",
				Benefit: "test benefit",
				Kind:    fix.ActionEdit,
				Path:    f.Evidence["config"],
				Transform: func(in []byte) ([]byte, error) {
					return append(append([]byte(nil), in...), []byte(marker)...), nil
				},
				VerifyCmd: []string{"sshd", "-t", "-f", fix.VerifyPathToken},
			}},
		}, nil
	})
	return r
}

func verifySetup(t *testing.T, r *verifyRunner, marker string) (*Engine, string, model.Finding) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, []byte("PermitRootLogin no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := New(Config{Fixes: verifiedFix(marker), Store: history.NewStore(t.TempDir()), Runner: r})
	f := model.NewFinding("ssh.testfix", "test", model.SeverityHigh,
		model.SourceSSH, model.RemediationAuto, model.WithEvidence("config", path))
	return e, path, f
}

// The whole point: a fix that would produce a file the service refuses must
// not touch the host. sshd keeps serving from the config it already loaded,
// so a broken sshd_config looks like nothing at all until the next restart —
// and repairing it then needs the SSH access it just removed.
func TestAFixThatWouldBreakTheConfigIsRefusedBeforeWriting(t *testing.T) {
	r := &verifyRunner{accept: func(c string) bool { return !strings.Contains(c, "BROKEN") }}
	e, path, f := verifySetup(t, r, "BROKEN\n")

	_, err := e.ApplyFix(context.Background(), f, 0)
	if err == nil {
		t.Fatal("a fix producing a rejected config must fail")
	}
	if !strings.Contains(err.Error(), "sshd rejects") {
		t.Errorf("the error should name the validator: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != "PermitRootLogin no\n" {
		t.Errorf("the live file was modified by a refused fix:\n%s", after)
	}
	// Refused before the backup, so there is nothing to undo and no
	// checkpoint cluttering the history.
	if cps, _ := e.ListCheckpoints(); len(cps) != 0 {
		t.Errorf("a refused fix left %d checkpoint(s)", len(cps))
	}
}

// A validator that rejects the file already in service is not judging our
// edit — it is failing to run. `sshd -t` needs to read the host keys, so on
// a host where it cannot, it fails on every config including the working
// one. Blocking the fix there would be the checker's inability masquerading
// as a verdict.
func TestAValidatorThatRejectsTheOriginalIsIgnored(t *testing.T) {
	r := &verifyRunner{accept: func(string) bool { return false }}
	e, path, f := verifySetup(t, r, "PasswordAuthentication no\n")

	if _, err := e.ApplyFix(context.Background(), f, 0); err != nil {
		t.Fatalf("a validator that cannot run must not block the fix: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), "PasswordAuthentication no") {
		t.Errorf("the fix was not applied:\n%s", after)
	}
}

// No validator on this host is not a failed validation either, and it must
// not cost a subprocess.
func TestAMissingValidatorSkipsTheCheck(t *testing.T) {
	r := &verifyRunner{absent: true, accept: func(string) bool { return false }}
	e, path, f := verifySetup(t, r, "PasswordAuthentication no\n")

	if _, err := e.ApplyFix(context.Background(), f, 0); err != nil {
		t.Fatalf("a host with no validator must still apply the fix: %v", err)
	}
	if r.calls != 0 {
		t.Errorf("the validator was run %d times despite not being installed", r.calls)
	}
	if after, _ := os.ReadFile(path); !strings.Contains(string(after), "PasswordAuthentication no") {
		t.Error("the fix was not applied")
	}
}

// The ordinary path: validator present, original good, result good.
func TestAValidFixPassesVerification(t *testing.T) {
	r := &verifyRunner{accept: func(string) bool { return true }}
	e, path, f := verifySetup(t, r, "PasswordAuthentication no\n")

	if _, err := e.ApplyFix(context.Background(), f, 0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if r.calls != 2 {
		t.Errorf("expected a control run and a check run, got %d calls", r.calls)
	}
	if after, _ := os.ReadFile(path); !strings.Contains(string(after), "PasswordAuthentication no") {
		t.Error("the fix was not applied")
	}
}
