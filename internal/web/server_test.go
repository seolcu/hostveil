package web

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

func TestHealthEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	ts := httptest.NewServer(secureHeaders(mux))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %q", body["status"])
	}
}

func TestSecureHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {})

	ts := httptest.NewServer(secureHeaders(mux))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected nosniff, got %q", resp.Header.Get("X-Content-Type-Options"))
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("expected no-referrer, got %q", resp.Header.Get("Referrer-Policy"))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("expected no-store, got %q", resp.Header.Get("Cache-Control"))
	}
}

func TestIsAddrInUse(t *testing.T) {
	addrInUse := &net.OpError{
		Op:   "listen",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8787},
		Err:  &os.SyscallError{Syscall: "bind", Err: syscall.EADDRINUSE},
	}
	if !isAddrInUse(addrInUse) {
		t.Error("expected true for EADDRINUSE error")
	}

	otherErr := &net.OpError{
		Op:   "listen",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8787},
		Err:  &os.SyscallError{Syscall: "bind", Err: syscall.EACCES},
	}
	if isAddrInUse(otherErr) {
		t.Error("expected false for non-EADDRINUSE error")
	}

	if isAddrInUse(errors.New("some other error")) {
		t.Error("expected false for unrelated error")
	}
}

func TestListenerInodes(t *testing.T) {
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:2253 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890
   2: 00000000:2253 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 99999
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	inodes, err := listenerInodes(path, 8787)
	if err != nil {
		t.Fatal(err)
	}
	if len(inodes) != 1 {
		t.Fatalf("expected 1 inode for port 8787, got %d", len(inodes))
	}
	if _, ok := inodes["12345"]; !ok {
		t.Error("expected inode 12345 for port 8787")
	}

	inodes, err = listenerInodes(path, 8080)
	if err != nil {
		t.Fatal(err)
	}
	if len(inodes) != 1 {
		t.Fatalf("expected 1 inode for port 8080, got %d", len(inodes))
	}
	if _, ok := inodes["67890"]; !ok {
		t.Error("expected inode 67890 for port 8080")
	}

	inodes, err = listenerInodes(path, 9999)
	if err != nil {
		t.Fatal(err)
	}
	if len(inodes) != 0 {
		t.Errorf("expected 0 inodes for non-existent port, got %d", len(inodes))
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	data := map[string]interface{}{
		"name":  "test",
		"count": 42,
	}
	writeJSON(rec, data)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["name"] != "test" {
		t.Errorf("expected test, got %v", decoded["name"])
	}
	if v, ok := decoded["count"].(float64); !ok || v != 42 {
		t.Errorf("expected 42, got %v", decoded["count"])
	}
}

func TestHandleFixNoRegistry(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/fix", nil)
	rec := httptest.NewRecorder()
	handleFix(rec, req, Options{})

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleFixInvalidBody(t *testing.T) {
	reg := fix.New()
	body := `not json`
	req := httptest.NewRequest("POST", "/api/fix", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleFix(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Error("expected success false")
	}
}

func TestHandleFixCrossOrigin(t *testing.T) {
	reg := fix.New()
	req := httptest.NewRequest("POST", "/api/fix", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handleFix(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Error("expected success false")
	}
}

func TestHandleFixCrossOrigin_BypassAttempt(t *testing.T) {
	reg := fix.New()
	// Attempt to bypass prefix check: host is "127.0.0.1:8787"
	req := httptest.NewRequest("POST", "/api/fix", nil)
	req.Host = "127.0.0.1:8787"
	req.Header.Set("Origin", "http://127.0.0.1:8787.evil.com")
	rec := httptest.NewRecorder()
	handleFix(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Error("expected success false for bypass attempt")
	}
}

func TestHandleFixCrossOrigin_ValidOrigin(t *testing.T) {
	reg := fix.New()
	reg.Register(&fix.Fix{
		FindingID: "test",
		Label:     "Test",
		Actions:   []fix.Action{{Apply: func(ctx fix.Context) error { return nil }}},
	})
	req := httptest.NewRequest("POST", "/api/fix", strings.NewReader(`{"finding":{"id":"test"},"action_index":0}`))
	req.Host = "127.0.0.1:8787"
	req.Header.Set("Origin", "http://127.0.0.1:8787")
	rec := httptest.NewRecorder()
	handleFix(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != true {
		t.Errorf("expected success true for valid origin, got %v", resp)
	}
}

func TestHandleFixNoFix(t *testing.T) {
	reg := fix.New()
	body := `{"finding":{"id":"unknown-finding"},"action_index":0}`
	req := httptest.NewRequest("POST", "/api/fix", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleFix(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Error("expected success false")
	}
	if resp["error"] != "no fix registered for this finding" {
		t.Errorf("unexpected error: %v", resp["error"])
	}
}

func TestHandleFixSuccess(t *testing.T) {
	reg := fix.New()
	reg.Register(&fix.Fix{
		FindingID: "test-finding",
		Label:     "Test Fix",
		Actions: []fix.Action{
			{
				Label: "Apply fix",
				Apply: func(ctx fix.Context) error {
					return nil
				},
			},
		},
	})
	body := `{"finding":{"id":"test-finding"},"action_index":0}`
	req := httptest.NewRequest("POST", "/api/fix", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleFix(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != true {
		t.Errorf("expected success true, got %v", resp["success"])
	}
}

func TestHandleFixBatch_NoRegistry(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/fix/batch", nil)
	rec := httptest.NewRecorder()
	handleFixBatch(rec, req, Options{})

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleFixBatch_InvalidBody(t *testing.T) {
	reg := fix.New()
	body := `not json`
	req := httptest.NewRequest("POST", "/api/fix/batch", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleFixBatch(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Error("expected success false")
	}
}

func TestHandleFixBatch_CrossOrigin(t *testing.T) {
	reg := fix.New()
	req := httptest.NewRequest("POST", "/api/fix/batch", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handleFixBatch(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Error("expected success false")
	}
}

func TestHandleFixBatch_Success(t *testing.T) {
	reg := fix.New()
	reg.Register(&fix.Fix{
		FindingID: "test-a",
		Label:     "Fix A",
		Actions: []fix.Action{{
			Label: "Apply A",
			Apply: func(ctx fix.Context) error { return nil },
		}},
	})
	reg.Register(&fix.Fix{
		FindingID: "test-b",
		Label:     "Fix B",
		Actions: []fix.Action{{
			Label: "Apply B",
			Apply: func(ctx fix.Context) error { return nil },
		}},
	})
	body := `{"findings":[{"id":"test-a"},{"id":"test-b"}],"action_index":0}`
	req := httptest.NewRequest("POST", "/api/fix/batch", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleFixBatch(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	results, ok := resp["results"].([]interface{})
	if !ok {
		t.Fatal("expected results array")
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		entry := r.(map[string]interface{})
		if entry["success"] != true {
			t.Errorf("result[%d] expected success true, got %v", i, entry["success"])
		}
	}
}

func TestHandleFixBatch_WithAlsoFixed(t *testing.T) {
	reg := fix.New()
	reg.Register(&fix.Fix{
		FindingID: "trivy.cve-*",
		Label:     "Fix CVE",
		Actions: []fix.Action{{
			Label: "Apply",
			Apply: func(ctx fix.Context) error { return nil },
		}},
	})
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "trivy.cve-2024-1234", Service: "nginx:latest"},
		{ID: "trivy.cve-2024-5678", Service: "nginx:latest"},
	})
	live.MarkFixed("trivy.cve-2024-1234")

	body := `{"findings":[{"id":"trivy.cve-2024-1234","Service":"nginx:latest"}],"action_index":0}`
	req := httptest.NewRequest("POST", "/api/fix/batch", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleFixBatch(rec, req, Options{Fixes: reg, Live: live})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	alsoFixed, ok := resp["also_fixed"].([]interface{})
	if !ok {
		t.Fatal("expected also_fixed array")
	}
	if len(alsoFixed) != 1 {
		t.Fatalf("expected 1 also_fixed, got %d", len(alsoFixed))
	}
	if alsoFixed[0].(string) != "trivy.cve-2024-5678" {
		t.Errorf("expected also_fixed trivy.cve-2024-5678, got %v", alsoFixed[0])
	}
}

func TestHandleExport_JSON(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "test.001", Title: "Test finding", Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
	})
	live.Finalize()

	req := httptest.NewRequest("GET", "/api/export?format=json", nil)
	rec := httptest.NewRecorder()
	handleExport(rec, req, live)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Error("expected Content-Disposition header")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	findings, ok := body["findings"].([]interface{})
	if !ok {
		t.Fatal("expected findings array")
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestHandleExport_CSV(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "test.001", Title: "Test finding", Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
	})
	live.Finalize()

	req := httptest.NewRequest("GET", "/api/export?format=csv", nil)
	rec := httptest.NewRecorder()
	handleExport(rec, req, live)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("expected text/csv, got %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Error("expected Content-Disposition header")
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "ID,Severity,Source,Service,Title,Remediation,Fixed") {
		t.Errorf("expected CSV header, got: %q", body[:50])
	}
	if !strings.Contains(body, "test.001") {
		t.Error("expected finding ID in CSV body")
	}
}

func TestHandleRescan(t *testing.T) {
	live := domain.NewScanProgress(true)
	reg := fix.New()
	req := httptest.NewRequest("POST", "/api/rescan", nil)
	rec := httptest.NewRecorder()
	handleRescan(rec, req, Options{Live: live, Fixes: reg, rescanMu: &sync.Mutex{}})

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "rescanning" {
		t.Errorf("expected status rescanning, got %q", body["status"])
	}
}

func TestServeStaticAssets(t *testing.T) {
	staticFS, err := fs.Sub(assets, "assets")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServerFS(staticFS))
	ts := httptest.NewServer(secureHeaders(mux))
	defer ts.Close()

	t.Run("index_html", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "text/html") {
			t.Errorf("expected text/html, got %q", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), `<script src="/app.js">`) {
			t.Error("expected app.js script tag in index.html")
		}
		if !strings.Contains(string(body), `<link rel="stylesheet" href="/app.css"`) {
			t.Error("expected app.css stylesheet link in index.html")
		}
	})

	t.Run("app_js", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/app.js")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for app.js, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "javascript") && !strings.Contains(ct, "ecmascript") {
			t.Errorf("expected javascript content type, got %q", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		if len(body) < 100 {
			t.Errorf("app.js too short: %d bytes", len(body))
		}
		if !strings.Contains(string(body), "async function init") {
			t.Error("expected init function in app.js")
		}
	})

	t.Run("app_css", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/app.css")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for app.css, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "css") {
			t.Errorf("expected css content type, got %q", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		if len(body) < 100 {
			t.Errorf("app.css too short: %d bytes", len(body))
		}
	})

	t.Run("secure_headers", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("expected nosniff, got %q", resp.Header.Get("X-Content-Type-Options"))
		}
		if resp.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("expected no-referrer, got %q", resp.Header.Get("Referrer-Policy"))
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("expected no-store, got %q", resp.Header.Get("Cache-Control"))
		}
	})
}

func TestHandleResult_VariousStates(t *testing.T) {
	t.Run("loading_state", func(t *testing.T) {
		live := domain.NewScanProgress(true)
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/result", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, live.Snapshot())
		})
		ts := httptest.NewServer(secureHeaders(mux))
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/api/result")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		var snap domain.Snapshot
		if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
			t.Fatal(err)
		}
		if snap.Phase != "loading" {
			t.Errorf("expected phase loading, got %q", snap.Phase)
		}
		if snap.Score != 0 {
			t.Errorf("expected score 0 during loading, got %d", snap.Score)
		}
		if len(snap.Tools) != 2 {
			t.Errorf("expected 2 tools, got %d", len(snap.Tools))
		}
		if snap.Tools["trivy"].Status != 0 {
			t.Errorf("expected trivy status pending (0), got %d", snap.Tools["trivy"].Status)
		}
	})

	t.Run("complete_state", func(t *testing.T) {
		live := domain.NewScanProgress(true)
		findings := []domain.Finding{
			{ID: "test.001", Title: "Critical issue", Severity: domain.SeverityCritical, Source: domain.SourceTrivy},
			{ID: "test.002", Title: "High issue", Severity: domain.SeverityHigh, Source: domain.SourceLynis},
		}
		live.AddFindings(findings)
		live.SetToolStatus("trivy", domain.ToolDone, "Found 1 issues")
		live.SetToolStatus("lynis", domain.ToolDone, "Found 1 issues")
		live.Finalize()

		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/result", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, live.Snapshot())
		})
		ts := httptest.NewServer(secureHeaders(mux))
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/api/result")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		var snap domain.Snapshot
		if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
			t.Fatal(err)
		}
		if snap.Phase != "complete" {
			t.Errorf("expected phase complete, got %q", snap.Phase)
		}
		if snap.Score == 0 {
			t.Error("expected non-zero score in complete state")
		}
		if len(snap.Findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(snap.Findings))
		}
		if len(snap.ScoreBreakdown.Axes) != 4 {
			t.Errorf("expected 4 score axes, got %d", len(snap.ScoreBreakdown.Axes))
		}
	})

	t.Run("with_fixed_finding", func(t *testing.T) {
		live := domain.NewScanProgress(true)
		findings := []domain.Finding{
			{ID: "fixable.001", Title: "Fixable", Severity: domain.SeverityCritical, Source: domain.SourceTrivy},
			{ID: "fixable.002", Title: "Fixed one", Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
		}
		live.AddFindings(findings)
		live.SetToolStatus("trivy", domain.ToolDone, "Found 2 issues")
		live.SetToolStatus("lynis", domain.ToolDone, "Found 0 issues")
		live.Finalize()
		live.MarkFixed("fixable.002")

		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/result", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, live.Snapshot())
		})
		ts := httptest.NewServer(secureHeaders(mux))
		defer ts.Close()

		resp, err := http.Get(ts.URL + "/api/result")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		var result struct {
			Findings []struct {
				ID    string `json:"id"`
				Fixed bool   `json:"fixed"`
			} `json:"findings"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		for _, f := range result.Findings {
			if f.ID == "fixable.002" && !f.Fixed {
				t.Error("expected fixable.002 to be marked fixed")
			}
			if f.ID == "fixable.001" && f.Fixed {
				t.Error("expected fixable.001 to remain unfixed")
			}
		}
	})
}

func TestHandleRescan_Concurrency(t *testing.T) {
	live := domain.NewScanProgress(true)
	reg := fix.New()
	mu := &sync.Mutex{}
	mu.Lock()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/rescan", nil)
	handleRescan(rec, req, Options{Live: live, Fixes: reg, rescanMu: mu})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Error("expected rescan to be rejected when one is already in progress")
	}
	if resp["error"] != "rescan already in progress" {
		t.Errorf("unexpected error: %v", resp["error"])
	}
	mu.Unlock()
}

func TestHandleExport_FormatValidation(t *testing.T) {
	t.Run("empty_findings_csv", func(t *testing.T) {
		live := domain.NewScanProgress(true)
		live.Finalize()

		req := httptest.NewRequest("GET", "/api/export?format=csv", nil)
		rec := httptest.NewRecorder()
		handleExport(rec, req, live)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.HasPrefix(body, "ID,Severity,Source,Service,Title,Remediation,Fixed") {
			t.Errorf("expected CSV header, got %q", body[:50])
		}
		lines := strings.Split(strings.TrimSpace(body), "\n")
		if len(lines) != 1 {
			t.Errorf("expected 1 line (header only) for empty findings, got %d", len(lines))
		}
	})

	t.Run("csv_escaping", func(t *testing.T) {
		live := domain.NewScanProgress(true)
		live.AddFindings([]domain.Finding{
			{ID: "csv.test", Title: `Contains "quotes" and, commas`, Severity: domain.SeverityMedium, Source: domain.SourceTrivy},
		})
		live.Finalize()

		req := httptest.NewRequest("GET", "/api/export?format=csv", nil)
		rec := httptest.NewRecorder()
		handleExport(rec, req, live)

		body := rec.Body.String()
		if !strings.Contains(body, `"Contains ""quotes"" and, commas"`) {
			t.Errorf("expected CSV-escaped title, got: %q", body)
		}
	})

	t.Run("unknown_format_defaults_to_json", func(t *testing.T) {
		live := domain.NewScanProgress(true)
		live.Finalize()

		req := httptest.NewRequest("GET", "/api/export?format=xml", nil)
		rec := httptest.NewRecorder()
		handleExport(rec, req, live)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected application/json for unknown format, got %q", ct)
		}
	})

	t.Run("no_format_query_defaults_to_json", func(t *testing.T) {
		live := domain.NewScanProgress(true)
		live.Finalize()

		req := httptest.NewRequest("GET", "/api/export", nil)
		rec := httptest.NewRecorder()
		handleExport(rec, req, live)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected application/json for empty format, got %q", ct)
		}
	})
}

func TestHandleExport_ContentDisposition(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.Finalize()

	t.Run("json_disposition", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/export?format=json", nil)
		rec := httptest.NewRecorder()
		handleExport(rec, req, live)

		cd := rec.Header().Get("Content-Disposition")
		if !strings.Contains(cd, "hostveil-report.json") {
			t.Errorf("expected hostveil-report.json in Content-Disposition, got %q", cd)
		}
	})

	t.Run("csv_disposition", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/export?format=csv", nil)
		rec := httptest.NewRecorder()
		handleExport(rec, req, live)

		cd := rec.Header().Get("Content-Disposition")
		if !strings.Contains(cd, "hostveil-report.csv") {
			t.Errorf("expected hostveil-report.csv in Content-Disposition, got %q", cd)
		}
	})
}

func TestSameOrigin(t *testing.T) {
	tests := []struct {
		origin string
		host   string
		want   bool
	}{
		{"http://127.0.0.1:8787", "127.0.0.1:8787", true},
		{"https://127.0.0.1:8787", "127.0.0.1:8787", true},
		{"http://evil.com", "127.0.0.1:8787", false},
		{"http://127.0.0.1:8787.evil.com", "127.0.0.1:8787", false},
		{"ftp://127.0.0.1:8787", "127.0.0.1:8787", false},
		{"http://localhost:8787", "localhost:8787", true},
		{"", "127.0.0.1:8787", false},
		{"not-a-url", "127.0.0.1:8787", false},
	}
	for _, tt := range tests {
		got := sameOrigin(tt.origin, tt.host)
		if got != tt.want {
			t.Errorf("sameOrigin(%q, %q) = %v, want %v", tt.origin, tt.host, got, tt.want)
		}
	}
}

func TestHandleDismiss(t *testing.T) {
	live := domain.NewScanProgress(true)
	body := `{"finding_id":"test.001","dismissed":true}`
	req := httptest.NewRequest("POST", "/api/dismiss", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleDismiss(rec, req, Options{Live: live})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != true {
		t.Errorf("expected success true, got %v", resp["success"])
	}
	if resp["dismissed"] != true {
		t.Errorf("expected dismissed true, got %v", resp["dismissed"])
	}
	if !live.IsDismissed("test.001") {
		t.Error("expected finding to be dismissed in Live state")
	}
}

func TestHandleDismiss_Undismiss(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.DismissFinding("test.001")

	body := `{"finding_id":"test.001","dismissed":false}`
	req := httptest.NewRequest("POST", "/api/dismiss", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleDismiss(rec, req, Options{Live: live})

	if live.IsDismissed("test.001") {
		t.Error("expected finding to be undismissed")
	}
}

func TestHandleDismiss_InvalidBody(t *testing.T) {
	live := domain.NewScanProgress(true)
	req := httptest.NewRequest("POST", "/api/dismiss", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()
	handleDismiss(rec, req, Options{Live: live})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Errorf("expected success false, got %v", resp["success"])
	}
}

func TestHandleDismiss_CrossOrigin(t *testing.T) {
	live := domain.NewScanProgress(true)
	body := `{"finding_id":"test.001","dismissed":true}`
	req := httptest.NewRequest("POST", "/api/dismiss", strings.NewReader(body))
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handleDismiss(rec, req, Options{Live: live})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Errorf("expected success false for cross-origin, got %v", resp["success"])
	}
}

func TestHandleFix_InfoOnly(t *testing.T) {
	reg := fix.New()
	reg.Register(&fix.Fix{
		FindingID: "test.finding",
		Label:     "Test fix",
		Actions: []fix.Action{
			{
				Type:  fix.ActionExec,
				Label: "Apply",
				Apply: func(ctx fix.Context) error { return nil },
			},
		},
	})

	body := `{"finding":{"id":"test.finding"},"action_index":0,"info_only":true}`
	req := httptest.NewRequest("POST", "/api/fix", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleFix(rec, req, Options{Fixes: reg})

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != true {
		t.Errorf("expected success true for info_only, got %v", resp["success"])
	}
	actions, ok := resp["actions"].([]interface{})
	if !ok {
		t.Fatal("expected actions array")
	}
	if len(actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(actions))
	}
}

func TestHandleRescan_CrossOrigin(t *testing.T) {
	live := domain.NewScanProgress(true)
	reg := fix.New()
	req := httptest.NewRequest("POST", "/api/rescan", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	// Use the mux setup which has the origin check, not handleRescan directly
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/rescan", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !sameOrigin(origin, r.Host) {
			writeJSON(w, map[string]interface{}{"success": false, "error": "rejected: cross-origin request"})
			return
		}
		handleRescan(w, r, Options{Live: live, Fixes: reg, rescanMu: &sync.Mutex{}})
	})
	mux.ServeHTTP(rec, req)

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != false {
		t.Errorf("expected false for cross-origin, got %v", resp["success"])
	}
}
