package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

func reviewFinding(id, title string) model.Finding {
	f := model.NewFinding(id, title, model.SeverityHigh, model.SourceSSH, model.RemediationReview)
	f.FixBenefit = "gets you something"
	f.FixSideEffect = "costs you something"
	return f
}

func TestFixableActiveExcludesManualAndUnavailableAndInactive(t *testing.T) {
	auto := model.NewFinding("a", "auto one", model.SeverityLow, model.SourceSSH, model.RemediationAuto)
	auto.FixBenefit = "x"
	review := reviewFinding("r", "review one")
	manual := model.NewFinding("m", "manual one", model.SeverityMedium, model.SourceCompose, model.RemediationManual)
	unavailable := model.NewFinding("u", "unavailable one", model.SeverityMedium, model.SourceCVE, model.RemediationUnavailable)
	fixed := reviewFinding("f", "already fixed")
	fixed.Fixed = true

	out := fixableActive([]model.Finding{auto, review, manual, unavailable, fixed})
	if len(out) != 2 {
		t.Fatalf("fixableActive returned %d findings, want 2 (auto + review): %+v", len(out), out)
	}
}

func TestPlainAdviceListsBenefitAndSideEffect(t *testing.T) {
	f := reviewFinding("ssh.rootlogin", "SSH permits root login")
	got := plainAdvice([]model.Finding{f})
	if !strings.Contains(got, "SSH permits root login") {
		t.Error("plainAdvice is missing the finding's title")
	}
	if !strings.Contains(got, "gets you something") || !strings.Contains(got, "costs you something") {
		t.Error("plainAdvice is missing Benefit/SideEffect")
	}
}

func TestPlainAdviceWithNothingFixable(t *testing.T) {
	got := plainAdvice(nil)
	if got == "" {
		t.Error("plainAdvice should say something even with nothing to judge")
	}
}

// The AGENTS.md invariant: every score, explanation, and fix must work
// with ai.Noop. useAI=false is the "not asked" path — Plain is always
// there, and nothing AI-shaped is attempted.
func TestAdvisePlainWorksWithoutAI(t *testing.T) {
	e := New(Config{Store: history.NewStore(t.TempDir())})
	adv := e.Advise(context.Background(), []model.Finding{reviewFinding("r", "review one")}, false)
	if adv.Plain == "" {
		t.Error("Plain must be populated even with ai.Noop")
	}
	if adv.AI != "" || adv.AIError != "" {
		t.Error("useAI=false should not touch AI or AIError")
	}
}

// core.New defaults an unset Config.AI to ai.Noop, which reports itself
// unavailable — so asking for AI with nothing configured is the same
// honest "no AI provider is reachable" answer Explain already gives, not a
// silent success.
func TestAdviseWithAIRequestedButNothingConfigured(t *testing.T) {
	e := New(Config{Store: history.NewStore(t.TempDir())})
	adv := e.Advise(context.Background(), []model.Finding{reviewFinding("r", "review one")}, true)
	if adv.AIError == "" {
		t.Error("expected an AIError when no AI provider is configured")
	}
	if adv.Plain == "" {
		t.Error("Plain must still be populated")
	}
}

func TestAdviseWithAI(t *testing.T) {
	fake := &fakeExplainer{available: true, text: "1. Apply"}
	e := New(Config{AI: fake, Store: history.NewStore(t.TempDir())})
	if err := e.SetAIContext("a personal media server"); err != nil {
		t.Fatal(err)
	}
	adv := e.Advise(context.Background(), []model.Finding{reviewFinding("r", "review one")}, true)
	if adv.AI != "1. Apply" {
		t.Errorf("AI = %q", adv.AI)
	}
	if fake.gotSiteContext != "a personal media server" {
		t.Errorf("Advise passed siteContext = %q, want the saved text", fake.gotSiteContext)
	}
}

func TestAdviseSkipsTheAICallWithNothingFixable(t *testing.T) {
	fake := &fakeExplainer{available: true, text: "should not be seen"}
	e := New(Config{AI: fake, Store: history.NewStore(t.TempDir())})
	manual := model.NewFinding("m", "manual one", model.SeverityMedium, model.SourceCompose, model.RemediationManual)
	adv := e.Advise(context.Background(), []model.Finding{manual}, true)
	if fake.called {
		t.Error("Advise should not call the AI provider when there is nothing fixable to judge")
	}
	if adv.AI != "" {
		t.Errorf("AI = %q, want empty", adv.AI)
	}
}

func TestAdviseAIError(t *testing.T) {
	fake := &fakeExplainer{available: true, err: errors.New("model not pulled")}
	e := New(Config{AI: fake, Store: history.NewStore(t.TempDir())})
	adv := e.Advise(context.Background(), []model.Finding{reviewFinding("r", "review one")}, true)
	if !strings.Contains(adv.AIError, "model not pulled") {
		t.Errorf("AIError = %q", adv.AIError)
	}
}
