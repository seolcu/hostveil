package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

const maxOllamaResponse = 256 << 10

// Ollama is an Explainer backed by a local Ollama server. It keeps all
// data on the host by default.
type Ollama struct {
	Host  string // e.g. http://127.0.0.1:11434
	Model string // e.g. llama3.2
	http  *http.Client
}

// NewOllama builds an Ollama provider, reading HOSTVEIL_OLLAMA_HOST and
// HOSTVEIL_OLLAMA_MODEL when set, with local defaults.
//
// A trailing slash on the host is trimmed. Host is used as a prefix — the
// paths are appended to it — so "http://x:11434/" used to build
// "http://x:11434//api/version". Ollama itself tolerates that, which is what
// let it survive: the double slash is invisible until something in front of
// Ollama does not tolerate it, and then the symptom is that the AI says
// nothing, on a path where saying nothing is also what success looks like
// when no server is running.
func NewOllama() *Ollama {
	host := strings.TrimRight(envOr("HOSTVEIL_OLLAMA_HOST", "http://127.0.0.1:11434"), "/")
	modelName := envOr("HOSTVEIL_OLLAMA_MODEL", "llama3.2")
	return &Ollama{Host: host, Model: modelName, http: &http.Client{Timeout: 60 * time.Second}}
}

// Available reports whether the Ollama server responds.
func (o *Ollama) Available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	endpoint, err := o.endpoint("/api/version")
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type generateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type generateResponse struct {
	Response string `json:"response"`
}

// Explain asks the local model for an advisory explanation of the finding.
func (o *Ollama) Explain(ctx context.Context, f model.Finding, siteContext string) (string, error) {
	return o.complete(ctx, buildPrompt(f, siteContext), 120)
}

// Advise asks the local model to judge a whole batch of findings against
// siteContext at once.
func (o *Ollama) Advise(ctx context.Context, findings []model.Finding, siteContext string) (string, error) {
	return o.complete(ctx, buildAdvisePrompt(findings, siteContext), 500)
}

// complete sends prompt to the local model and returns its response,
// capped to wordCap words. Shared by Explain and Advise, which differ only
// in what prompt they build and how long an answer makes sense.
func (o *Ollama) complete(ctx context.Context, prompt string, wordCap int) (string, error) {
	body, err := json.Marshal(generateRequest{Model: o.Model, Prompt: prompt, Stream: false})
	if err != nil {
		return "", err
	}
	endpoint, err := o.endpoint("/api/generate")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("contacting Ollama: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned %s (is the model %q pulled?)", resp.Status, o.Model)
	}
	var gr generateResponse
	limited := io.LimitReader(resp.Body, maxOllamaResponse+1)
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&gr); err != nil {
		return "", err
	}
	if decoder.InputOffset() > maxOllamaResponse {
		return "", fmt.Errorf("ollama response exceeds %d bytes", maxOllamaResponse)
	}
	return limitWords(gr.Response, wordCap), nil
}

func (o *Ollama) endpoint(path string) (string, error) {
	s, err := safeEndpoint(o.Host, path)
	if err != nil {
		return "", fmt.Errorf("invalid Ollama host: %w", err)
	}
	return s, nil
}

func limitWords(s string, max int) string {
	words := strings.Fields(s)
	if len(words) <= max {
		return s
	}
	return strings.Join(words[:max], " ") + "…"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
