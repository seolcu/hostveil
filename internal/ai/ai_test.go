package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func TestNoopIsInert(t *testing.T) {
	var n Noop
	if n.Available(context.Background()) {
		t.Error("Noop must never be available")
	}
	if out, err := n.Explain(context.Background(), model.Finding{}); err != nil || out != "" {
		t.Errorf("Noop.Explain = (%q, %v), want empty", out, err)
	}
}

// TestPromptRedactsEvidence verifies the prompt never carries raw evidence
// values (which can include secrets or paths) off the host — only the
// human-readable finding fields are sent.
func TestPromptRedactsEvidence(t *testing.T) {
	f := model.NewFinding("compose.dr005", "Hardcoded secret", model.SeverityHigh,
		model.SourceCompose, model.RemediationManual,
		model.WithService("db"),
		model.WithDescription("A secret is stored in plaintext."),
		model.WithHowToFix("Move it to a .env file."),
		model.WithEvidence("variable", "POSTGRES_PASSWORD"),
		model.WithEvidence("secret_value", "hunter2-super-secret"),
		model.WithMetadata("file", "/etc/very/secret/path.yml"),
	)
	prompt := buildPrompt(f)

	if strings.Contains(prompt, "hunter2-super-secret") {
		t.Error("prompt leaked a secret evidence value")
	}
	if strings.Contains(prompt, "/etc/very/secret/path.yml") {
		t.Error("prompt leaked a file path")
	}
	if !strings.Contains(prompt, "Hardcoded secret") || !strings.Contains(prompt, "db") {
		t.Error("prompt should include the title and service")
	}
}
