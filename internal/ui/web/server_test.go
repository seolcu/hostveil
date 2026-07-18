package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

type fakeRunner struct {
	present map[string]bool
	lsJSON  string
}

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("nope")
}
func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "docker" && strings.Join(args, " ") == "compose ls --all --format json" {
		return []byte(f.lsJSON), nil
	}
	return nil, errors.New("unexpected")
}

func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := core.New(core.Config{
		Registry: check.NewRegistry(composecheck.New()),
		Fixes:    fix.Default(),
		Store:    history.NewStore(t.TempDir()),
		Runner:   fakeRunner{present: map[string]bool{"docker": true}, lsJSON: `[{"Name":"demo","ConfigFiles":"` + path + `"}]`},
	})
	engine.Scan(context.Background(), nil)
	return New(engine, "127.0.0.1:0"), path
}

func TestResultEndpoint(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/result")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var report model.Report
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 {
		t.Error("expected findings in result")
	}
}

func TestDNSRebindGuard(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/result", nil)
	req.Host = "evil.example.com"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("evil host should be forbidden, got %d", rec.Code)
	}
}

func TestCSRFGuard(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/rescan", nil)
	req.Host = "127.0.0.1:8787"
	req.Header.Set("Origin", "http://evil.example.com")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST should be forbidden, got %d", rec.Code)
	}
}

func TestFixThroughAPI(t *testing.T) {
	s, path := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := strings.NewReader(`{"id":"compose.ds018","service":"cache","action":0}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/fix", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fix returned %d", resp.StatusCode)
	}
	var outcome model.FixOutcome
	_ = json.NewDecoder(resp.Body).Decode(&outcome)
	if !outcome.Success {
		t.Errorf("fix not successful: %+v", outcome)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "127.0.0.1:6379:6379") {
		t.Errorf("fix not applied to file:\n%s", data)
	}
}

func TestFixBatchThroughAPI(t *testing.T) {
	s, path := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := strings.NewReader(`{"findings":[{"id":"compose.ds018","service":"cache"}]}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/fix/batch", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("batch fix returned %d", resp.StatusCode)
	}
	var outcome model.BatchOutcome
	_ = json.NewDecoder(resp.Body).Decode(&outcome)
	if len(outcome.Applied) != 1 || outcome.Applied[0] != "compose.ds018" {
		t.Errorf("expected ds018 applied, got %+v", outcome)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "127.0.0.1:6379:6379") {
		t.Errorf("batch fix not applied to file:\n%s", data)
	}
}

func TestDashboardServed(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard returned %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "html") {
		t.Errorf("dashboard content-type = %q", ct)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("missing CSP header")
	}
}
