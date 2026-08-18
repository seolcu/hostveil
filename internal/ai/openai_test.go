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

func TestOpenAICompatExplainAsksForOneResponseRatherThanAStream(t *testing.T) {
	var got openAIRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Explain used %s, want POST", r.Method)
		}
		if r.URL.Path != "/chat/completions" {
			t.Errorf("Explain posted to %s, want /chat/completions", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
			t.Errorf("Authorization = %q, want Bearer sk-test", got)
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("request body is not the JSON the API expects: %v", err)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"root login is how you lose the box"}}]}`)
	}))
	defer srv.Close()

	c := &OpenAICompat{BaseURL: srv.URL, APIKey: "sk-test", Model: "gpt-4o-mini", http: srv.Client()}
	out, err := c.Explain(context.Background(), finding())
	if err != nil {
		t.Fatal(err)
	}
	if out != "root login is how you lose the box" {
		t.Errorf("Explain returned %q", out)
	}
	if got.Stream {
		t.Error("Explain asked for a stream; the decoder reads one object, so the answer " +
			"would be silently truncated to the first chunk")
	}
	if got.Model != "gpt-4o-mini" {
		t.Errorf("Explain asked model %q, want the configured one", got.Model)
	}
	if !strings.Contains(got.Messages[0].Content, "root login") {
		t.Errorf("the prompt does not carry the finding: %q", got.Messages[0].Content)
	}
}

func TestOpenAICompatExplainRequiresAModel(t *testing.T) {
	c := &OpenAICompat{BaseURL: "https://api.openai.com/v1", APIKey: "sk-test", http: http.DefaultClient}
	if _, err := c.Explain(context.Background(), finding()); err == nil {
		t.Fatal("Explain accepted an empty model")
	}
}

func TestOpenAICompatExplainDoesNotSendAnAuthHeaderWithNoKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want none for a keyless local server", got)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer srv.Close()

	c := &OpenAICompat{BaseURL: srv.URL, Model: "local-model", http: srv.Client()}
	if _, err := c.Explain(context.Background(), finding()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAICompatExplainNamesTheVendorWhenItRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &OpenAICompat{BaseURL: srv.URL, APIKey: "sk-bad", Model: "gpt-4o-mini", http: srv.Client()}
	_, err := c.Explain(context.Background(), finding())
	if err == nil {
		t.Fatal("Explain returned no error for a 401")
	}
	if !strings.Contains(err.Error(), "gpt-4o-mini") {
		t.Errorf("error does not name the model: %v", err)
	}
}

func TestOpenAICompatExplainRejectsUnsafeOrAmbiguousBaseURLs(t *testing.T) {
	for _, base := range []string{"file:///tmp/socket", "https://user:pass@api.openai.com/v1", "https://api.openai.com/v1?target=elsewhere"} {
		c := &OpenAICompat{BaseURL: base, Model: "x", http: http.DefaultClient}
		if _, err := c.Explain(context.Background(), finding()); err == nil {
			t.Errorf("Explain accepted base URL %q", base)
		}
	}
}

func TestOpenAICompatExplainBoundsAndCapsTheResponse(t *testing.T) {
	long := strings.Repeat("word ", 140)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(openAIResponse{Choices: []openAIChoice{{Message: openAIMessage{Content: long}}}})
	}))
	defer srv.Close()
	c := &OpenAICompat{BaseURL: srv.URL, Model: "x", http: srv.Client()}
	got, err := c.Explain(context.Background(), finding())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(got)); n != 120 {
		t.Fatalf("response has %d words, want 120", n)
	}

	tooLarge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"`+strings.Repeat("x", maxOpenAIResponse)+`"}}]}`)
	}))
	defer tooLarge.Close()
	c = &OpenAICompat{BaseURL: tooLarge.URL, Model: "x", http: tooLarge.Client()}
	if _, err := c.Explain(context.Background(), finding()); err == nil {
		t.Fatal("Explain accepted an oversized response")
	}
}

func TestOpenAICompatAvailable(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("Available probed %s, want /models", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer bad.Close()

	if c := (&OpenAICompat{BaseURL: ok.URL, Model: "x", http: ok.Client()}); !c.Available(context.Background()) {
		t.Error("Available said no to a server answering 200")
	}
	if c := (&OpenAICompat{BaseURL: bad.URL, Model: "x", http: bad.Client()}); c.Available(context.Background()) {
		t.Error("Available said yes to a 401")
	}
	if c := (&OpenAICompat{BaseURL: ok.URL, Model: "", http: ok.Client()}); c.Available(context.Background()) {
		t.Error("Available said yes with no model configured")
	}
}

func TestOpenAICompatAvailableGivesUpOnAServerThatNeverAnswers(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer func() { close(block); srv.Close() }()

	c := &OpenAICompat{BaseURL: srv.URL, Model: "x", http: srv.Client()}
	done := make(chan bool, 1)
	start := time.Now()
	go func() { done <- c.Available(context.Background()) }()
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

func TestNewOpenAICompatReadsTheEnvironment(t *testing.T) {
	t.Setenv("HOSTVEIL_OPENAI_BASE_URL", "")
	t.Setenv("HOSTVEIL_OPENAI_API_KEY", "")
	t.Setenv("HOSTVEIL_OPENAI_MODEL", "")
	c := NewOpenAICompat()
	if c.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("default BaseURL = %q, want the OpenAI origin", c.BaseURL)
	}
	if c.Model != "" {
		t.Errorf("default Model = %q, want empty — there is no cross-vendor default", c.Model)
	}

	t.Setenv("HOSTVEIL_OPENAI_BASE_URL", "https://openrouter.ai/api/v1/")
	t.Setenv("HOSTVEIL_OPENAI_API_KEY", "sk-or-test")
	t.Setenv("HOSTVEIL_OPENAI_MODEL", "meta-llama/llama-3.1-8b-instruct")
	c = NewOpenAICompat()
	if c.BaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("BaseURL = %q, want the trailing slash trimmed", c.BaseURL)
	}
	if c.APIKey != "sk-or-test" || c.Model != "meta-llama/llama-3.1-8b-instruct" {
		t.Errorf("NewOpenAICompat = %q/%q, want the environment's values", c.APIKey, c.Model)
	}
}
