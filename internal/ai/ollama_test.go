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

	"github.com/seolcu/hostveil/internal/model"
)

// The Ollama provider had no tests at all. Being advisory is a reason for it
// never to break anything else, not a reason for it to be unchecked: it is
// still the code behind `explain --ai`, the TUI's `e` key and the dashboard's
// AI button, and every way it fails quietly here reads to a user as "the AI
// said nothing" with no way to tell that from "the AI was not asked".

func finding() model.Finding {
	return model.NewFinding("ssh.rootlogin", "SSH permits root login",
		model.SeverityHigh, model.SourceSSH, model.RemediationReview)
}

// stream:false is the difference between one JSON object and a stream of
// them. Ollama answers a streaming request with newline-delimited objects,
// and json.Decoder would happily decode the first and stop — so the user
// would get the first few tokens of an explanation, with nothing anywhere
// reporting a truncation. It is one field and it is load-bearing.
func TestExplainAsksForOneResponseRatherThanAStream(t *testing.T) {
	var got generateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Explain used %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/generate" {
			t.Errorf("Explain posted to %s, want /api/generate", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type is %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("request body is not the JSON Ollama expects: %v", err)
		}
		_, _ = io.WriteString(w, `{"response":"root login is how you lose the box"}`)
	}))
	defer srv.Close()

	o := &Ollama{Host: srv.URL, Model: "llama3.2", http: srv.Client()}
	out, err := o.Explain(context.Background(), finding())
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
	if got.Model != "llama3.2" {
		t.Errorf("Explain asked model %q, want the configured one", got.Model)
	}
	if !strings.Contains(got.Prompt, "ssh.rootlogin") && !strings.Contains(got.Prompt, "root login") {
		t.Errorf("the prompt does not carry the finding: %q", got.Prompt)
	}
}

// The status message is the one a user reads when nothing comes back, so it
// has to say what to do. "ollama returned 404" is not actionable; naming the
// model is, because a model that was never pulled is the usual cause.
func TestExplainSaysWhichModelWhenTheServerRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	o := &Ollama{Host: srv.URL, Model: "a-model-nobody-pulled", http: srv.Client()}
	_, err := o.Explain(context.Background(), finding())
	if err == nil {
		t.Fatal("Explain returned no error for a 404")
	}
	if !strings.Contains(err.Error(), "a-model-nobody-pulled") {
		t.Errorf("error does not name the model: %v", err)
	}
}

func TestExplainReportsAnUnreachableServer(t *testing.T) {
	// Port 1 refuses immediately on every platform this builds for.
	o := &Ollama{Host: "http://127.0.0.1:1", Model: "x", http: &http.Client{Timeout: time.Second}}
	if _, err := o.Explain(context.Background(), finding()); err == nil {
		t.Fatal("Explain returned no error with nothing listening")
	}
}

func TestAvailable(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/version" {
			t.Errorf("Available probed %s, want /api/version", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"version":"0.1.0"}`)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	if o := (&Ollama{Host: ok.URL, http: ok.Client()}); !o.Available(context.Background()) {
		t.Error("Available said no to a server answering 200")
	}
	// A server that is up and unwell is not a server that can explain
	// anything. Reporting it available would offer the user a button that
	// then fails.
	if o := (&Ollama{Host: bad.URL, http: bad.Client()}); o.Available(context.Background()) {
		t.Error("Available said yes to a 500")
	}
	if o := (&Ollama{Host: "http://127.0.0.1:1", http: &http.Client{Timeout: time.Second}}); o.Available(context.Background()) {
		t.Error("Available said yes with nothing listening")
	}
}

// Available is called on the path that draws a UI, so a hung Ollama must cost
// a couple of seconds and not the session. The bound is inside Available
// rather than in the caller, which is why it is tested here.
func TestAvailableGivesUpOnAServerThatNeverAnswers(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer func() { close(block); srv.Close() }()

	o := &Ollama{Host: srv.URL, http: srv.Client()}
	done := make(chan bool, 1)
	start := time.Now()
	go func() { done <- o.Available(context.Background()) }()
	select {
	case got := <-done:
		if got {
			t.Error("Available said yes to a server that never answered")
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("Available took %v to give up; the UI waits on this", d)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Available never returned — a hung Ollama hangs the interface")
	}
}

func TestNewOllamaReadsTheEnvironment(t *testing.T) {
	t.Setenv("HOSTVEIL_OLLAMA_HOST", "")
	t.Setenv("HOSTVEIL_OLLAMA_MODEL", "")
	o := NewOllama()
	if o.Host != "http://127.0.0.1:11434" {
		t.Errorf("default host is %q — nothing should leave the machine by default", o.Host)
	}
	if o.Model == "" {
		t.Error("default model is empty")
	}
	if o.http == nil {
		t.Fatal("NewOllama built a provider with no HTTP client")
	}
	if o.http.Timeout == 0 {
		t.Error("the HTTP client has no timeout, so one wedged request waits forever")
	}

	t.Setenv("HOSTVEIL_OLLAMA_HOST", "http://ollama.internal:11434")
	t.Setenv("HOSTVEIL_OLLAMA_MODEL", "qwen2.5")
	o = NewOllama()
	if o.Host != "http://ollama.internal:11434" || o.Model != "qwen2.5" {
		t.Errorf("NewOllama = %q/%q, want the environment's values", o.Host, o.Model)
	}
}

// A trailing slash used to produce http://host//api/version. Ollama tolerates
// it, which is what made it survive: it is invisible until something in front
// of Ollama does not, and then the failure is "the AI said nothing".
func TestATrailingSlashOnTheHostIsNotADifferentServer(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = io.WriteString(w, `{"response":"ok"}`)
	}))
	defer srv.Close()

	t.Setenv("HOSTVEIL_OLLAMA_HOST", srv.URL+"/")
	o := NewOllama()
	o.http = srv.Client()
	if !o.Available(context.Background()) {
		t.Fatal("Available failed against a host given with a trailing slash")
	}
	if _, err := o.Explain(context.Background(), finding()); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.HasPrefix(p, "//") {
			t.Errorf("requested %q — the trailing slash reached the path", p)
		}
	}
}
