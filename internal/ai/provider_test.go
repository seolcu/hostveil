package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func finding() model.Finding {
	return model.NewFinding("ssh.rootlogin", "SSH permits root login",
		model.SeverityHigh, model.SourceSSH, model.RemediationReview)
}

func TestFromEnvDefaultsToALocalOllama(t *testing.T) {
	t.Setenv("HOSTVEIL_AI_PROVIDER", "")
	t.Setenv("HOSTVEIL_OLLAMA_HOST", "")
	t.Setenv("HOSTVEIL_OLLAMA_MODEL", "")
	c, ok := FromEnv().(*OpenAICompat)
	if !ok || c.BaseURL != "http://127.0.0.1:11434/v1" || c.Model != "llama3.2" {
		t.Errorf("FromEnv() = %#v, want the local Ollama when HOSTVEIL_AI_PROVIDER is unset — nothing should leave the host by default", FromEnv())
	}
}

func TestFromEnvSelectsByName(t *testing.T) {
	t.Setenv("HOSTVEIL_OPENAI_BASE_URL", "")
	t.Setenv("HOSTVEIL_OLLAMA_HOST", "")
	t.Setenv("HOSTVEIL_AI_PROVIDER", "anthropic")
	if _, ok := FromEnv().(*Anthropic); !ok {
		t.Errorf("anthropic: FromEnv() = %T, want *Anthropic", FromEnv())
	}
	for name, base := range map[string]string{
		"ollama": "http://127.0.0.1:11434/v1",
		"openai": "https://api.openai.com/v1",
	} {
		t.Setenv("HOSTVEIL_AI_PROVIDER", name)
		if c, ok := FromEnv().(*OpenAICompat); !ok || c.BaseURL != base {
			t.Errorf("%s: FromEnv() = %#v, want an OpenAI-compatible client at %s", name, FromEnv(), base)
		}
	}
}

// The Ollama preset reaches Ollama's OpenAI-compatible routes under the host
// it was given, and its errors name the Ollama variables rather than the
// HOSTVEIL_OPENAI_* ones the operator never set.
func TestOllamaUsesTheV1RoutesAndNamesItsOwnVariables(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/v1/chat/completions" {
			var req openAIRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Model != "qwen" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("HOSTVEIL_OLLAMA_HOST", srv.URL+"/")
	t.Setenv("HOSTVEIL_OLLAMA_MODEL", "qwen")
	c := NewOllama()
	if !c.Available(context.Background()) {
		t.Fatal("Available() = false against a server answering /v1/models")
	}
	if got, err := c.Explain(context.Background(), finding(), ""); err != nil || got != "ok" {
		t.Fatalf("Explain = %q, %v", got, err)
	}
	if strings.Join(paths, " ") != "/v1/models /v1/chat/completions" {
		t.Errorf("requested %v, want /v1/models then /v1/chat/completions", paths)
	}

	c.Model = "missing"
	_, err := c.Explain(context.Background(), finding(), "")
	if err == nil || !strings.Contains(err.Error(), "HOSTVEIL_OLLAMA_MODEL") || strings.Contains(err.Error(), "OPENAI") {
		t.Errorf("error = %v, want it to name HOSTVEIL_OLLAMA_MODEL and nothing about OpenAI", err)
	}
}

func TestFromEnvNamesTheBadValueRatherThanSilentlyFallingBack(t *testing.T) {
	t.Setenv("HOSTVEIL_AI_PROVIDER", "chatgpt")
	e := FromEnv()
	if !e.Available(context.Background()) {
		t.Fatal("unknownProvider must report Available so Explain actually runs and surfaces the bad value")
	}
	_, err := e.Explain(context.Background(), finding(), "")
	if err == nil || !strings.Contains(err.Error(), "chatgpt") {
		t.Errorf("Explain error = %v, want it to name the misconfigured value", err)
	}
}
