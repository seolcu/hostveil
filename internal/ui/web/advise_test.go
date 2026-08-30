package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
)

func TestAdviseRequiresToken(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/advise", nil)
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAdviseBeforeAnyScanIsConflict(t *testing.T) {
	s := New(core.New(core.Config{
		Registry: check.NewRegistry(),
		Fixes:    fix.Default(),
		Store:    history.NewStore(t.TempDir()),
	}), "127.0.0.1:0", Opts{Theme: "nord", Layout: "lanes"})

	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodGet, "/api/advise", nil))
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("no scan yet: status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestAdviseCarriesThePlainListing(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodGet, "/api/advise", nil))
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var adv struct {
		Plain string `json:"plain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &adv); err != nil {
		t.Fatal(err)
	}
	if adv.Plain == "" {
		t.Error("advise returned no plain listing")
	}
}

func TestAIContextRoundTripsThroughGetAndPost(t *testing.T) {
	s, _ := testServer(t)

	get := func() string {
		rec := httptest.NewRecorder()
		req := authed(s, httptest.NewRequest(http.MethodGet, "/api/ai-context", nil))
		req.Host = "127.0.0.1:8787"
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET status = %d, body: %s", rec.Code, rec.Body.String())
		}
		var got struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got.Text
	}

	if got := get(); got != "" {
		t.Fatalf("fresh engine's context = %q, want empty", got)
	}

	body, err := json.Marshal(struct {
		Text string `json:"text"`
	}{"a personal media server, favors fast patches over stability"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodPost, "/api/ai-context", bytes.NewReader(body)))
	req.Host = "127.0.0.1:8787"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, body: %s", rec.Code, rec.Body.String())
	}

	if got := get(); got != "a personal media server, favors fast patches over stability" {
		t.Errorf("context after POST = %q, want the saved text", got)
	}
}

func TestAIContextSetRequiresSameOrigin(t *testing.T) {
	s, _ := testServer(t)
	body, err := json.Marshal(struct {
		Text string `json:"text"`
	}{"attacker-controlled"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodPost, "/api/ai-context", bytes.NewReader(body)))
	req.Host = "127.0.0.1:8787"
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
