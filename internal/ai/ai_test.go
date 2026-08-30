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
	if out, err := n.Explain(context.Background(), model.Finding{}, ""); err != nil || out != "" {
		t.Errorf("Noop.Explain = (%q, %v), want empty", out, err)
	}
	if out, err := n.Advise(context.Background(), nil, ""); err != nil || out != "" {
		t.Errorf("Noop.Advise = (%q, %v), want empty", out, err)
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
	prompt := buildPrompt(f, "")

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

// A supplied siteContext must reach the prompt, and switches on the
// "For this host:" instruction — the whole reason it exists.
func TestPromptCarriesSiteContextWhenGiven(t *testing.T) {
	f := model.NewFinding("ssh.rootlogin", "SSH permits root login", model.SeverityHigh,
		model.SourceSSH, model.RemediationReview)

	without := buildPrompt(f, "")
	if strings.Contains(without, "operator describes this host") {
		t.Error("prompt mentions site context when none was given")
	}

	with := buildPrompt(f, "a personal media server")
	if !strings.Contains(with, "a personal media server") {
		t.Error("prompt does not carry the supplied site context")
	}
	if !strings.Contains(with, "For this host:") {
		t.Error("prompt does not ask for a situational verdict when context is given")
	}
}

// The batch prompt carries the same redaction discipline as buildPrompt —
// evidence never leaves the host, even across a whole list of findings.
func TestAdvisePromptRedactsEvidence(t *testing.T) {
	f := model.NewFinding("compose.dr005", "Hardcoded secret", model.SeverityHigh,
		model.SourceCompose, model.RemediationManual,
		model.WithService("db"),
		model.WithEvidence("secret_value", "hunter2-super-secret"),
		model.WithMetadata("file", "/etc/very/secret/path.yml"),
	)
	prompt := buildAdvisePrompt([]model.Finding{f}, "")

	if strings.Contains(prompt, "hunter2-super-secret") {
		t.Error("advise prompt leaked a secret evidence value")
	}
	if strings.Contains(prompt, "/etc/very/secret/path.yml") {
		t.Error("advise prompt leaked a file path")
	}
	if !strings.Contains(prompt, "Hardcoded secret") {
		t.Error("advise prompt should include the finding's title")
	}
}
