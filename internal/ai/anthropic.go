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

const (
	defaultAnthropicBaseURL = "https://api.anthropic.com"
	anthropicVersion        = "2023-06-01"
	maxAnthropicResponse    = 256 << 10
)

// Anthropic is an Explainer backed by the Claude API. Unlike Ollama it is a
// paid, off-host service, so FromEnv never selects it unless an operator sets
// HOSTVEIL_AI_PROVIDER=anthropic explicitly.
type Anthropic struct {
	BaseURL string // defaults to the real API; overridable so tests never dial out
	APIKey  string
	Model   string
	http    *http.Client
}

// NewAnthropic builds a Claude provider from ANTHROPIC_API_KEY — the name
// every Anthropic tool reads, so a key already exported for another tool
// works here with no extra setup — and HOSTVEIL_ANTHROPIC_MODEL.
func NewAnthropic() *Anthropic {
	return &Anthropic{
		BaseURL: defaultAnthropicBaseURL,
		APIKey:  os.Getenv("ANTHROPIC_API_KEY"),
		Model:   envOr("HOSTVEIL_ANTHROPIC_MODEL", "claude-opus-5"),
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (a *Anthropic) baseURL() string {
	if a.BaseURL != "" {
		return a.BaseURL
	}
	return defaultAnthropicBaseURL
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicOutputConfig sets effort to "low": an explanation capped at 120
// words is a simple task, and a lower effort keeps the model from spending
// its (billed) adaptive-thinking budget on a one-paragraph advisory note.
type anthropicOutputConfig struct {
	Effort string `json:"effort,omitempty"`
}

type anthropicRequest struct {
	Model        string                 `json:"model"`
	MaxTokens    int                    `json:"max_tokens"`
	Messages     []anthropicMessage     `json:"messages"`
	OutputConfig *anthropicOutputConfig `json:"output_config,omitempty"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicResponse struct {
	Content []anthropicContentBlock `json:"content"`
}

// Available checks that a key is configured and the account can reach the
// Models API. That endpoint is metadata only, so — unlike Explain — checking
// it costs no tokens, the same property Ollama's /api/version check has.
func (a *Anthropic) Available(ctx context.Context) bool {
	if a.APIKey == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL()+"/v1/models?limit=1", nil)
	if err != nil {
		return false
	}
	a.setHeaders(req)
	resp, err := a.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Explain asks Claude for an advisory explanation of the finding.
func (a *Anthropic) Explain(ctx context.Context, f model.Finding, siteContext string) (string, error) {
	return a.complete(ctx, buildPrompt(f, siteContext), 120)
}

// Advise asks Claude to judge a whole batch of findings against
// siteContext at once.
func (a *Anthropic) Advise(ctx context.Context, findings []model.Finding, siteContext string) (string, error) {
	return a.complete(ctx, buildAdvisePrompt(findings, siteContext), 500)
}

// complete sends prompt to the Claude API and returns its response, capped
// to wordCap words. Shared by Explain and Advise.
func (a *Anthropic) complete(ctx context.Context, prompt string, wordCap int) (string, error) {
	if a.APIKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY is not set")
	}
	body, err := json.Marshal(anthropicRequest{
		Model:        a.Model,
		MaxTokens:    2048,
		Messages:     []anthropicMessage{{Role: "user", Content: prompt}},
		OutputConfig: &anthropicOutputConfig{Effort: "low"},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL()+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	a.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("contacting the Claude API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the Claude API returned %s (check ANTHROPIC_API_KEY and that model %q is available on it)", resp.Status, a.Model)
	}
	var ar anthropicResponse
	limited := io.LimitReader(resp.Body, maxAnthropicResponse+1)
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&ar); err != nil {
		return "", err
	}
	if decoder.InputOffset() > maxAnthropicResponse {
		return "", fmt.Errorf("claude response exceeds %d bytes", maxAnthropicResponse)
	}
	var text strings.Builder
	for _, block := range ar.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	return limitWords(text.String(), wordCap), nil
}

func (a *Anthropic) setHeaders(req *http.Request) {
	req.Header.Set("x-api-key", a.APIKey)
	req.Header.Set("anthropic-version", anthropicVersion)
}
