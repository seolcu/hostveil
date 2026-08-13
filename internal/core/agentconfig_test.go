package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// commentedAgentConfig is the file this whole path exists for: JSON5 with the
// operator's own reasoning written into it. If a fix reflows this, the fix is
// worse than no fix — the operator opens the file afterwards and cannot find
// what they wrote or tell what hostveil changed.
const commentedAgentConfig = `{
  "gateway": {
    // "so I can reach it from the tablet in the kitchen"
    "bind": "lan",
    "controlUi": {
      // "the login kept logging me out while I was setting it up"
      "allowInsecureAuth": true,
    },
  },
  // "it couldn't restart my containers without this"
  "tools": { "elevated": { "enabled": true } },
  "notes": "guide: https://docs.openclaw.ai/gateway/security",
}
`

func agentConfigFinding(t *testing.T, path string) model.Finding {
	t.Helper()
	return model.NewFinding("agent.elevated-enabled",
		"Agent is permitted to run elevated commands",
		model.SeverityHigh, model.SourceAgent, model.RemediationAuto,
		model.WithService("alice:openclaw"),
		model.WithEvidence("config", path),
		model.WithEvidence("settings", "tools.elevated.enabled"),
		model.WithEvidence("set", "tools.elevated.enabled=false"),
	)
}

// TestAgentConfigApplyRollbackRoundTrip is the differentiator on the file
// type that motivated internal/json5: apply changes exactly one value, every
// comment survives, and rollback restores the file byte for byte.
func TestAgentConfigApplyRollbackRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openclaw.json")
	if err := os.WriteFile(path, []byte(commentedAgentConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	e := fixEngine(t)
	f := agentConfigFinding(t, path)

	out, err := e.ApplyFix(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(after)
	if !strings.Contains(got, `"enabled": false`) {
		t.Errorf("the value was not changed:\n%s", got)
	}
	for _, keep := range []string{
		`// "so I can reach it from the tablet in the kitchen"`,
		`// "the login kept logging me out while I was setting it up"`,
		`// "it couldn't restart my containers without this"`,
		`"notes": "guide: https://docs.openclaw.ai/gateway/security"`,
		`"allowInsecureAuth": true,`,
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("apply dropped %q from the operator's config:\n%s", keep, got)
		}
	}

	// One line changed, which is what makes the diff reviewable.
	before := strings.Split(commentedAgentConfig, "\n")
	nowLines := strings.Split(got, "\n")
	if len(before) != len(nowLines) {
		t.Fatalf("line count changed, %d -> %d:\n%s", len(before), len(nowLines), got)
	}
	changed := 0
	for i := range before {
		if before[i] != nowLines[i] {
			changed++
		}
	}
	if changed != 1 {
		t.Errorf("%d lines changed, want 1:\n%s", changed, got)
	}

	if out.CheckpointID == "" {
		t.Fatal("no checkpoint recorded, so the fix is not reversible")
	}
	if _, err := e.Rollback(out.CheckpointID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != commentedAgentConfig {
		t.Errorf("rollback did not restore the file byte for byte:\n%s", restored)
	}
}

// TestAgentConfigApplyRefusesASymlinkedTarget is the obligation register.go
// records for any fix reaching into a home: the account owns every component
// of that path, hostveil is root, and a preview renders whatever it read.
func TestAgentConfigApplyRefusesASymlinkedTarget(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.json")
	if err := os.WriteFile(secret, []byte(`{"tools":{"elevated":{"enabled":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "openclaw.json")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	e := fixEngine(t)
	f := agentConfigFinding(t, link)

	if _, err := e.PreviewFix(f); err == nil {
		t.Error("preview followed a symlink into a file it was not pointed at")
	}
	if _, err := e.ApplyFix(context.Background(), f, 0); err == nil {
		t.Error("apply followed a symlink into a file it was not pointed at")
	}
	// And nothing was written through it.
	still, err := os.ReadFile(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(still), `"enabled":true`) {
		t.Errorf("the symlink target was modified:\n%s", still)
	}
}
