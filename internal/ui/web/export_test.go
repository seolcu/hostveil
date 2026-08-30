package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
)

func TestExportRequiresToken(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/export?format=json", nil)
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestExportBeforeAnyScanIsConflict(t *testing.T) {
	// A fresh engine, never scanned, so Current() reports hasRun=false.
	s := New(core.New(core.Config{
		Registry: check.NewRegistry(),
		Fixes:    fix.Default(),
		Store:    history.NewStore(t.TempDir()),
	}), "127.0.0.1:0", Opts{Theme: "nord", Layout: "lanes"})

	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodGet, "/api/export?format=json", nil))
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("no scan yet: status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestExportUnknownFormatIsBadRequest(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodGet, "/api/export?format=yaml", nil))
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown format: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestExportEveryFormatServesTheRightContentTypeAndBody(t *testing.T) {
	s, _ := testServer(t)

	for _, f := range core.ExportFormats() {
		rec := httptest.NewRecorder()
		req := authed(s, httptest.NewRequest(http.MethodGet, "/api/export?format="+f.ID, nil))
		req.Host = "127.0.0.1:8787"
		s.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("format %s: status = %d, want 200; body: %s", f.ID, rec.Code, rec.Body.String())
			continue
		}
		if rec.Body.Len() == 0 {
			t.Errorf("format %s: empty body", f.ID)
		}
		cd := rec.Header().Get("Content-Disposition")
		if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "."+f.Ext) {
			t.Errorf("format %s: Content-Disposition = %q, want an attachment naming .%s", f.ID, cd, f.Ext)
		}
		if rec.Header().Get("Content-Type") == "" {
			t.Errorf("format %s: no Content-Type set", f.ID)
		}
	}
}
