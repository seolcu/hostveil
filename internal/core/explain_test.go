package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

type fakeExplainer struct {
	available bool
	text      string
	err       error
	called    bool
}

func (f *fakeExplainer) Available(context.Context) bool { return f.available }
func (f *fakeExplainer) Explain(context.Context, model.Finding) (string, error) {
	f.called = true
	return f.text, f.err
}

func sampleFinding() model.Finding {
	return model.NewFinding("ssh.rootlogin", "SSH permits root login", model.SeverityHigh,
		model.SourceSSH, model.RemediationReview,
		model.WithDescription("Root over SSH is a brute-force target."),
		model.WithHowToFix("Set PermitRootLogin prohibit-password."))
}

func TestExplainAlwaysHasPlain(t *testing.T) {
	e := New(Config{})
	exp := e.Explain(context.Background(), sampleFinding(), false)
	if !strings.Contains(exp.Plain, "SSH permits root login") {
		t.Errorf("plain explanation missing title: %q", exp.Plain)
	}
	if exp.AI != "" {
		t.Error("AI should be empty when useAI is false")
	}
}

func TestExplainNoAICallWhenDisabled(t *testing.T) {
	fake := &fakeExplainer{available: true, text: "ai text"}
	e := New(Config{AI: fake})
	e.Explain(context.Background(), sampleFinding(), false)
	if fake.called {
		t.Error("AI provider must not be called when useAI is false")
	}
}

func TestExplainWithAI(t *testing.T) {
	fake := &fakeExplainer{available: true, text: "  friendly explanation  "}
	e := New(Config{AI: fake})
	exp := e.Explain(context.Background(), sampleFinding(), true)
	if exp.AI != "friendly explanation" {
		t.Errorf("AI text = %q", exp.AI)
	}
	if exp.Plain == "" {
		t.Error("plain must still be present alongside AI")
	}
}

func TestExplainAIUnavailable(t *testing.T) {
	fake := &fakeExplainer{available: false}
	e := New(Config{AI: fake})
	exp := e.Explain(context.Background(), sampleFinding(), true)
	if exp.AIError == "" {
		t.Error("expected an AIError when the provider is unreachable")
	}
	if fake.called {
		t.Error("Explain should not be called when Available is false")
	}
}

func TestExplainAIError(t *testing.T) {
	fake := &fakeExplainer{available: true, err: errors.New("model not pulled")}
	e := New(Config{AI: fake})
	exp := e.Explain(context.Background(), sampleFinding(), true)
	if !strings.Contains(exp.AIError, "model not pulled") {
		t.Errorf("AIError = %q", exp.AIError)
	}
}
