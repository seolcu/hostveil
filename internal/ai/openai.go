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

const maxOpenAIResponse = 256 << 10

// OpenAICompat is an Explainer for any vendor that speaks the OpenAI chat
// completions shape — OpenAI itself, OpenRouter, Groq, Together, and most
// self-hosted inference servers. It is the escape hatch for a vendor neither
// Ollama nor the native Anthropic provider covers, not the recommended
// default.
type OpenAICompat struct {
	BaseURL string
	APIKey  string
	Model   string
	http    *http.Client
}

// NewOpenAICompat reads HOSTVEIL_OPENAI_BASE_URL, HOSTVEIL_OPENAI_API_KEY,
// and HOSTVEIL_OPENAI_MODEL. Unlike Ollama's model there is no cross-vendor
// default that would exist on every one of these services, so an unset
// HOSTVEIL_OPENAI_MODEL surfaces as a configuration error instead of
// silently guessing a model that may not exist on the configured vendor.
func NewOpenAICompat() *OpenAICompat {
	return &OpenAICompat{
		BaseURL: strings.TrimRight(envOr("HOSTVEIL_OPENAI_BASE_URL", "https://api.openai.com/v1"), "/"),
		APIKey:  os.Getenv("HOSTVEIL_OPENAI_API_KEY"),
		Model:   os.Getenv("HOSTVEIL_OPENAI_MODEL"),
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices"`
}

// Available reports whether a model is configured and the endpoint answers
// its (free, no-token-cost) model-listing route.
func (c *OpenAICompat) Available(ctx context.Context) bool {
	if c.Model == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	endpoint, err := safeEndpoint(c.BaseURL, "/models")
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	c.setAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Explain asks the configured vendor for an advisory explanation of the
// finding.
func (c *OpenAICompat) Explain(ctx context.Context, f model.Finding, siteContext string) (string, error) {
	return c.complete(ctx, buildPrompt(f, siteContext), 120)
}

// Advise asks the configured vendor to judge a whole batch of findings
// against siteContext at once.
func (c *OpenAICompat) Advise(ctx context.Context, findings []model.Finding, siteContext string) (string, error) {
	return c.complete(ctx, buildAdvisePrompt(findings, siteContext), 500)
}

// complete sends prompt to the configured vendor and returns its response,
// capped to wordCap words. Shared by Explain and Advise.
func (c *OpenAICompat) complete(ctx context.Context, prompt string, wordCap int) (string, error) {
	if c.Model == "" {
		return "", fmt.Errorf("HOSTVEIL_OPENAI_MODEL is not set")
	}
	body, err := json.Marshal(openAIRequest{
		Model:    c.Model,
		Messages: []openAIMessage{{Role: "user", Content: prompt}},
		Stream:   false,
	})
	if err != nil {
		return "", err
	}
	endpoint, err := safeEndpoint(c.BaseURL, "/chat/completions")
	if err != nil {
		return "", fmt.Errorf("invalid HOSTVEIL_OPENAI_BASE_URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("contacting %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s returned %s (check HOSTVEIL_OPENAI_MODEL=%q and HOSTVEIL_OPENAI_API_KEY)", c.BaseURL, resp.Status, c.Model)
	}
	var or openAIResponse
	limited := io.LimitReader(resp.Body, maxOpenAIResponse+1)
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&or); err != nil {
		return "", err
	}
	if decoder.InputOffset() > maxOpenAIResponse {
		return "", fmt.Errorf("response from %s exceeds %d bytes", c.BaseURL, maxOpenAIResponse)
	}
	if len(or.Choices) == 0 {
		return "", fmt.Errorf("%s returned no choices", c.BaseURL)
	}
	return limitWords(or.Choices[0].Message.Content, wordCap), nil
}

func (c *OpenAICompat) setAuth(req *http.Request) {
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
}
