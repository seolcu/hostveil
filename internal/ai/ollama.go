package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// Ollama is an Explainer backed by a local Ollama server. It keeps all
// data on the host by default.
type Ollama struct {
	Host  string // e.g. http://127.0.0.1:11434
	Model string // e.g. llama3.2
	http  *http.Client
}

// NewOllama builds an Ollama provider, reading HOSTVEIL_OLLAMA_HOST and
// HOSTVEIL_OLLAMA_MODEL when set, with local defaults.
func NewOllama() *Ollama {
	host := envOr("HOSTVEIL_OLLAMA_HOST", "http://127.0.0.1:11434")
	modelName := envOr("HOSTVEIL_OLLAMA_MODEL", "llama3.2")
	return &Ollama{Host: host, Model: modelName, http: &http.Client{Timeout: 60 * time.Second}}
}

// Available reports whether the Ollama server responds.
func (o *Ollama) Available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.Host+"/api/version", nil)
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
func (o *Ollama) Explain(ctx context.Context, f model.Finding) (string, error) {
	body, err := json.Marshal(generateRequest{Model: o.Model, Prompt: buildPrompt(f), Stream: false})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Host+"/api/generate", bytes.NewReader(body))
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
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", err
	}
	return gr.Response, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
