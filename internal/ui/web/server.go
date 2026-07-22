// Package web is hostveil's thin, localhost-bound web dashboard. Handlers
// marshal to/from core.Engine and nothing else — there is no detection,
// fix, scoring, or rollback logic here. It imports only core and model.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

//go:embed assets/*
var assets embed.FS

const maxBody = 1 << 20 // 1 MiB

// Server hosts the dashboard and API for one engine.
type Server struct {
	engine *core.Engine
	addr   string
	// theme is the palette the page starts in — the one hostveil resolved
	// from --theme, the environment, or the remembered choice. A theme picked
	// in the browser is stored there and overrides it for that browser only,
	// so two people pointed at the same dashboard can read it differently.
	theme string
}

// New builds a web Server bound to addr (e.g. "127.0.0.1:8787"), rendering in
// the theme named by themeID (see internal/ui/theme; an unknown or empty ID
// falls back to the default).
func New(engine *core.Engine, addr, themeID string) *Server {
	return &Server{engine: engine, addr: addr, theme: themeID}
}

// Handler builds the guarded HTTP handler (dashboard + API). Exposed so
// tests can exercise the routes and security middleware directly.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(mustSub())))
	// Generated from internal/ui/theme rather than shipped as static assets,
	// which is what keeps the dashboard's palette and the TUI's identical:
	// there is one registry of hexes and both read from it.
	mux.HandleFunc("/themes.css", s.handleThemesCSS)
	mux.HandleFunc("/theme.js", s.handleThemeJS)
	mux.HandleFunc("/api/result", s.handleResult)
	mux.HandleFunc("/api/preview", s.handlePreview)
	mux.HandleFunc("/api/fix", s.handleFix)
	mux.HandleFunc("/api/fix/all", s.handleFixAll)
	mux.HandleFunc("/api/fix/batch", s.handleFixBatch)
	mux.HandleFunc("/api/rescan", s.handleRescan)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/rollback", s.handleRollback)
	return s.guard(mux)
}

// ListenAndServe runs an initial scan, then serves the dashboard until the
// process exits.
func (s *Server) ListenAndServe() error {
	s.engine.Scan(context.Background(), nil)
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}

// guard applies the security middleware: a Host-header allowlist (DNS
// rebinding defense), same-origin enforcement on mutating requests, a body
// cap, and hardening headers. Kept in one place so every route is covered.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r) {
			http.Error(w, "cross-origin request blocked", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// hostAllowed permits only loopback hosts, blocking DNS-rebinding attacks
// that would let a malicious website reach the local dashboard.
func hostAllowed(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	switch h {
	case "127.0.0.1", "::1", "localhost", "":
		return true
	default:
		return false
	}
}

// sameOrigin ensures a mutating request originated from the dashboard
// itself, defending against CSRF.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// No Origin header (e.g. same-origin fetch in some browsers); fall
		// back to Referer, and allow when neither is present for curl-style
		// local use.
		ref := r.Header.Get("Referer")
		if ref == "" {
			return true
		}
		return hostFromURL(ref) == r.Host
	}
	return hostFromURL(origin) == r.Host
}

func hostFromURL(u string) string {
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	if i := strings.IndexAny(u, "/"); i >= 0 {
		u = u[:i]
	}
	return u
}

// --- handlers ---

func (s *Server) handleThemesCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	// No caching: the served default changes with --theme, and a stale
	// stylesheet would silently keep the previous run's palette.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, theme.CSS(s.theme))
}

func (s *Server) handleThemeJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, theme.JS(s.theme))
}

// resultPayload is the dashboard's view of a scan: the report, plus how it
// differs from the one before it. The engine already computes the delta on
// every scan; without this the dashboard would throw away the one thing
// that tells an operator whether their last round of fixes helped. Report
// is embedded so its JSON stays flat and the shape only gains a field.
type resultPayload struct {
	model.Report
	Delta model.Delta `json:"delta"`
}

func (s *Server) handleResult(w http.ResponseWriter, _ *http.Request) {
	report, _ := s.engine.Current()
	writeJSON(w, resultPayload{Report: report, Delta: s.engine.LastDelta()})
}

func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request) {
	report := s.engine.Scan(r.Context(), nil)
	writeJSON(w, resultPayload{Report: report, Delta: s.engine.LastDelta()})
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	f, ok := s.lookup(r.URL.Query().Get("id"), r.URL.Query().Get("service"))
	if !ok {
		http.Error(w, "no such finding", http.StatusNotFound)
		return
	}
	preview, err := s.engine.PreviewFix(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, preview)
}

type fixRequest struct {
	ID      string `json:"id"`
	Service string `json:"service"`
	Action  int    `json:"action"`
}

func (s *Server) handleFix(w http.ResponseWriter, r *http.Request) {
	var req fixRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f, ok := s.lookup(req.ID, req.Service)
	if !ok {
		http.Error(w, "no such finding", http.StatusNotFound)
		return
	}
	outcome, err := s.engine.ApplyFix(r.Context(), f, req.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, outcome)
}

func (s *Server) handleFixAll(w http.ResponseWriter, r *http.Request) {
	report, _ := s.engine.Current()
	var auto []model.Finding
	for _, f := range report.Findings {
		if !f.Fixed && f.Remediation == model.RemediationAuto {
			auto = append(auto, f)
		}
	}
	writeJSON(w, s.engine.ApplyBatch(r.Context(), auto))
}

type fixRef struct {
	ID      string `json:"id"`
	Service string `json:"service"`
}

type batchRequest struct {
	Findings []fixRef `json:"findings"`
}

// handleFixBatch applies exactly the findings the client selected. Each is
// resolved against the current report; ApplyBatch itself skips anything that
// is not a single-action Auto fix, reporting it under Skipped.
func (s *Server) handleFixBatch(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var sel []model.Finding
	for _, ref := range req.Findings {
		if f, ok := s.lookup(ref.ID, ref.Service); ok {
			sel = append(sel, f)
		}
	}
	writeJSON(w, s.engine.ApplyBatch(r.Context(), sel))
}

func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	cps, err := s.engine.ListCheckpoints()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, cps)
}

type rollbackRequest struct {
	CheckpointID string `json:"checkpoint_id"`
	// Force restores even when the file changed after the fix wrote it.
	// The dashboard asks first: rollback keeps no backup of its own, so
	// discarding those edits cannot be undone.
	Force bool `json:"force"`
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	var req rollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rollback := s.engine.Rollback
	if req.Force {
		rollback = s.engine.RollbackForce
	}
	out, err := rollback(req.CheckpointID)
	if err != nil {
		// 409 rather than 400 so the client can tell "this file changed
		// since the fix, confirm before discarding" apart from a genuine
		// failure. The engine declined; it did not fail.
		if core.IsExternalEdit(err) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, out)
}

// lookup finds an active finding by ID (and optional service).
func (s *Server) lookup(id, service string) (model.Finding, bool) {
	report, _ := s.engine.Current()
	for _, f := range report.Findings {
		if f.Fixed || f.ID != id {
			continue
		}
		if service == "" || f.Service == service {
			return f, true
		}
	}
	return model.Finding{}, false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// mustSub returns the embedded assets rooted at the assets/ directory so
// index.html is served at "/".
func mustSub() fs.FS {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err) // embedded FS is fixed at build time; this cannot fail
	}
	return sub
}

// URL returns the dashboard URL for logging.
func (s *Server) URL() string { return fmt.Sprintf("http://%s/", s.addr) }
