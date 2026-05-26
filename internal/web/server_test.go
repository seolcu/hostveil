package web

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	handleRescan(rec, req, Options{Live: live, Fixes: reg})

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
