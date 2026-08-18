package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnthropicExplainSendsTheKeyAndVersionHeader(t *testing.T) {
	var got anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Explain used %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/messages" {
			t.Errorf("Explain posted to %s, want /v1/messages", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "sk-test" {
			t.Errorf("x-api-key = %q, want sk-test", got)
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
			t.Errorf("anthropic-version = %q, want %q", got, anthropicVersion)
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("request body is not the JSON the Claude API expects: %v", err)
		}
		_, _ = io.WriteString(w, `{"content":[{"type":"thinking","text":"reasoning"},{"type":"text","text":"root login is how you lose the box"}]}`)
	}))
	defer srv.Close()

	a := &Anthropic{BaseURL: srv.URL, APIKey: "sk-test", Model: "claude-opus-5", http: srv.Client()}
	out, err := a.Explain(context.Background(), finding())
	if err != nil {
		t.Fatal(err)
	}
	if out != "root login is how you lose the box" {
		t.Errorf("Explain returned %q, want only the text block", out)
	}
	if got.Model != "claude-opus-5" {
		t.Errorf("Explain asked model %q, want the configured one", got.Model)
	}
	if got.OutputConfig == nil || got.OutputConfig.Effort != "low" {
		t.Errorf("Explain output_config.effort = %+v, want low", got.OutputConfig)
	}
	if !strings.Contains(got.Messages[0].Content, "root login") {
		t.Errorf("the prompt does not carry the finding: %q", got.Messages[0].Content)
	}
}

func TestAnthropicExplainNamesTheModelWhenTheAPIRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a := &Anthropic{BaseURL: srv.URL, APIKey: "sk-test", Model: "a-model-that-does-not-exist", http: srv.Client()}
	_, err := a.Explain(context.Background(), finding())
	if err == nil {
		t.Fatal("Explain returned no error for a 404")
	}
	if !strings.Contains(err.Error(), "a-model-that-does-not-exist") {
		t.Errorf("error does not name the model: %v", err)
	}
}

func TestAnthropicExplainRequiresAnAPIKey(t *testing.T) {
	a := &Anthropic{Model: "claude-opus-5", http: http.DefaultClient}
	if _, err := a.Explain(context.Background(), finding()); err == nil {
		t.Fatal("Explain accepted an empty API key")
	}
}

func TestAnthropicAvailable(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("Available probed %s, want /v1/models", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer bad.Close()

	if a := (&Anthropic{BaseURL: ok.URL, APIKey: "sk-test", http: ok.Client()}); !a.Available(context.Background()) {
		t.Error("Available said no to a server answering 200")
	}
	if a := (&Anthropic{BaseURL: bad.URL, APIKey: "sk-test", http: bad.Client()}); a.Available(context.Background()) {
		t.Error("Available said yes to a 401")
	}
	if a := (&Anthropic{BaseURL: ok.URL, APIKey: "", http: ok.Client()}); a.Available(context.Background()) {
		t.Error("Available said yes with no API key configured")
	}
}

func TestAnthropicAvailableGivesUpOnAServerThatNeverAnswers(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer func() { close(block); srv.Close() }()

	a := &Anthropic{BaseURL: srv.URL, APIKey: "sk-test", http: srv.Client()}
	done := make(chan bool, 1)
	start := time.Now()
	go func() { done <- a.Available(context.Background()) }()
	select {
	case got := <-done:
		if got {
			t.Error("Available said yes to a server that never answered")
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("Available took %v to give up", d)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Available never returned")
	}
}

func TestNewAnthropicReadsTheEnvironment(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("HOSTVEIL_ANTHROPIC_MODEL", "")
	a := NewAnthropic()
	if a.APIKey != "" {
		t.Errorf("APIKey = %q, want empty with ANTHROPIC_API_KEY unset", a.APIKey)
	}
	if a.Model != "claude-opus-5" {
		t.Errorf("default model = %q, want claude-opus-5", a.Model)
	}
	if a.BaseURL != defaultAnthropicBaseURL {
		t.Errorf("default BaseURL = %q, want %q", a.BaseURL, defaultAnthropicBaseURL)
	}

	t.Setenv("ANTHROPIC_API_KEY", "sk-live")
	t.Setenv("HOSTVEIL_ANTHROPIC_MODEL", "claude-haiku-4-5")
	a = NewAnthropic()
	if a.APIKey != "sk-live" || a.Model != "claude-haiku-4-5" {
		t.Errorf("NewAnthropic = %q/%q, want the environment's values", a.APIKey, a.Model)
	}
}
