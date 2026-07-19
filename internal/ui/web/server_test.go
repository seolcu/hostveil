package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

// TestHistoryAndRollbackThroughAPI is the web half of "reversible
// anywhere": a fix applied through the dashboard must be undoable through
// the dashboard, restoring the original bytes and bringing the finding
// back into the active list.
func TestHistoryAndRollbackThroughAPI(t *testing.T) {
	s, path := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	post := func(p, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+p, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", srv.URL)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s returned %d", p, resp.StatusCode)
		}
		return resp
	}

	fixResp := post("/api/fix", `{"id":"compose.ds018","service":"cache","action":0}`)
	var applied model.FixOutcome
	_ = json.NewDecoder(fixResp.Body).Decode(&applied)
	fixResp.Body.Close()
	if !applied.Success {
		t.Fatalf("fix not applied: %+v", applied)
	}

	// The history endpoint feeds the browser directly: it must carry a
	// materialized reversible flag and must not leak how backups are stored.
	histResp, err := http.Get(srv.URL + "/api/history")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(histResp.Body)
	histResp.Body.Close()
	if strings.Contains(string(raw), `"blob"`) {
		t.Errorf("/api/history leaks backup blob names to the client: %s", raw)
	}
	var cps []model.Checkpoint
	if err := json.Unmarshal(raw, &cps); err != nil {
		t.Fatal(err)
	}
	if len(cps) != 1 {
		t.Fatalf("want 1 checkpoint, got %d", len(cps))
	}
	if !cps[0].Reversible {
		t.Error("an edit fix's checkpoint must report reversible to the UI")
	}

	rbResp := post("/api/rollback", `{"checkpoint_id":"`+cps[0].ID+`"}`)
	var rb model.RollbackOutcome
	_ = json.NewDecoder(rbResp.Body).Decode(&rb)
	rbResp.Body.Close()
	if len(rb.RestoredFiles) != 1 {
		t.Errorf("unexpected restored files: %v", rb.RestoredFiles)
	}

	if data, _ := os.ReadFile(path); string(data) != string(orig) {
		t.Errorf("rollback did not restore original bytes:\nwant:\n%s\ngot:\n%s", orig, data)
	}

	// The finding must be back in the active list, or the dashboard would
	// show a clean host whose fix had just been undone.
	resResp, err := http.Get(srv.URL + "/api/result")
	if err != nil {
		t.Fatal(err)
	}
	defer resResp.Body.Close()
	var report model.Report
	_ = json.NewDecoder(resResp.Body).Decode(&report)
	var found bool
	for _, f := range report.Findings {
		if f.ID == "compose.ds018" && f.Service == "cache" {
			found = true
			if f.Fixed {
				t.Error("finding still marked fixed after rollback")
			}
		}
	}
	if !found {
		t.Error("rolled-back finding missing from the report")
	}
}

// TestRollbackRejectsUnknownCheckpoint keeps a bad ID from 500ing.
func TestRollbackRejectsUnknownCheckpoint(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/rollback",
		strings.NewReader(`{"checkpoint_id":"nope"}`))
	req.Host = "127.0.0.1:8787"
	req.Header.Set("Origin", "http://127.0.0.1:8787")
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown checkpoint should be a 400, got %d", rec.Code)
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
