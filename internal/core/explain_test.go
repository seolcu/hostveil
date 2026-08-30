package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

type fakeExplainer struct {
	available bool
	text      string
	err       error
	called    bool
	// gotSiteContext captures whatever Explain/Advise was actually called
	// with, so a test can assert Engine.Explain/Advise pass the saved
	// context through rather than dropping it.
	gotSiteContext string
}

func (f *fakeExplainer) Available(context.Context) bool { return f.available }
func (f *fakeExplainer) Explain(_ context.Context, _ model.Finding, siteContext string) (string, error) {
	f.called = true
	f.gotSiteContext = siteContext
	return f.text, f.err
}
func (f *fakeExplainer) Advise(_ context.Context, _ []model.Finding, siteContext string) (string, error) {
	f.called = true
	f.gotSiteContext = siteContext
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

// AIContext/SetAIContext round-trip through the engine's own state
// directory — Engine owns this directly (internal/core is not
// layering-restricted), unlike theme/layout's UI-injected Save callback.
func TestAIContextRoundTrip(t *testing.T) {
	e := New(Config{Store: history.NewStore(t.TempDir())})
	if got := e.AIContext(); got != "" {
		t.Errorf("AIContext before anything is set = %q, want empty", got)
	}
	if err := e.SetAIContext("a personal media server"); err != nil {
		t.Fatal(err)
	}
	if got := e.AIContext(); got != "a personal media server" {
		t.Errorf("AIContext = %q, want the saved text", got)
	}
	if err := e.SetAIContext(""); err != nil {
		t.Fatal(err)
	}
	if got := e.AIContext(); got != "" {
		t.Errorf("AIContext after clearing = %q, want empty", got)
	}
}

// Explain must pass the saved context through to the provider, not just
// keep it sitting in the state directory unused.
func TestExplainPassesTheSavedSiteContext(t *testing.T) {
	fake := &fakeExplainer{available: true, text: "ok"}
	e := New(Config{AI: fake, Store: history.NewStore(t.TempDir())})
	if err := e.SetAIContext("a personal media server"); err != nil {
		t.Fatal(err)
	}
	e.Explain(context.Background(), sampleFinding(), true)
	if fake.gotSiteContext != "a personal media server" {
		t.Errorf("Explain passed siteContext = %q, want the saved text", fake.gotSiteContext)
	}
}
