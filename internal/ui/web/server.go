// Package web is hostveil's thin, localhost-bound web dashboard. Handlers
// marshal to/from core.Engine and nothing else — there is no detection,
// fix, scoring, or rollback logic here. It imports only core and model.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

//go:embed assets/*
var assets embed.FS

const maxBody = 1 << 20 // 1 MiB

// sessionCookie carries the dashboard's access token after the first load.
const sessionCookie = "hostveil_session"

// Server hosts the dashboard and API for one engine.
type Server struct {
	engine *core.Engine
	addr   string
	// theme is the palette the page starts in — the one hostveil resolved
	// from --theme, the environment, or the remembered choice. A theme picked
	// in the browser is stored there and overrides it for that browser only,
	// so two people pointed at the same dashboard can read it differently.
	theme string
	// token gates every route. See newToken for why loopback alone is not
	// enough of a boundary here.
	token string
}

// New builds a web Server bound to addr (e.g. "127.0.0.1:8787"), rendering in
// the theme named by themeID (see internal/ui/theme; an unknown or empty ID
// falls back to the default).
func New(engine *core.Engine, addr, themeID string) *Server {
	return &Server{engine: engine, addr: addr, theme: themeID, token: newToken()}
}

// newToken mints the per-run access token.
//
// Binding to loopback keeps the dashboard off the network; it does not keep
// it away from other accounts on the same machine. hostveil auto-elevates
// for `serve`, so the dashboard runs as root, and every route it exposes
// applies fixes, rolls them back, or reads a scan of /etc/shadow and the
// compose files. Without a token any unprivileged local user — or any
// process, including a compromised container with host networking — could
// curl 127.0.0.1:8787/api/fix/all and have root edit files on their behalf.
// That is a privilege-escalation path, and the token is what closes it.
//
// A failure of the system CSPRNG is fatal rather than degraded: falling back
// to something guessable would leave the door open while reporting that it
// was shut.
func newToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("hostveil: cannot generate a dashboard access token: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Handler builds the guarded HTTP handler (dashboard + API). Exposed so
// tests can exercise the routes and security middleware directly.
//
// Every route names its method. That is not tidiness: the guard used to
// check the origin of POSTs only, while the handlers ignored the method
// entirely, so `<img src="http://127.0.0.1:8787/api/fix/all">` on any web
// page in the world made the dashboard apply every Auto fix on the host.
// Binding the method at the router means a route that mutates cannot be
// reached by the request shapes a browser will issue cross-origin without
// asking.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(mustSub())))
	// Generated from internal/ui/theme rather than shipped as static assets,
	// which is what keeps the dashboard's palette and the TUI's identical:
	// there is one registry of hexes and both read from it.
	mux.HandleFunc("GET /themes.css", s.handleThemesCSS)
	mux.HandleFunc("GET /theme.js", s.handleThemeJS)
	mux.HandleFunc("GET /api/result", s.handleResult)
	mux.HandleFunc("GET /api/preview", s.handlePreview)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("POST /api/fix", s.handleFix)
	mux.HandleFunc("POST /api/fix/all", s.handleFixAll)
	mux.HandleFunc("POST /api/fix/batch", s.handleFixBatch)
	mux.HandleFunc("POST /api/rescan", s.handleRescan)
	mux.HandleFunc("POST /api/rollback", s.handleRollback)
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
		// No WriteTimeout: a rescan legitimately takes minutes on a host with
		// many images, and cutting the response off mid-scan would look like a
		// crash. IdleTimeout still reaps connections nobody is using.
		IdleTimeout: 2 * time.Minute,
	}
	return srv.ListenAndServe()
}

// guard applies the security middleware: a Host-header allowlist (DNS
// rebinding defense), the access token, same-origin enforcement on mutating
// requests, a body cap, and hardening headers. Kept in one place so every
// route is covered.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if !s.authorize(w, r) {
			http.Error(w, "missing or invalid access token — open the URL hostveil printed at startup",
				http.StatusUnauthorized)
			return
		}
		if !isSafeMethod(r.Method) && !sameOrigin(r) {
			http.Error(w, "cross-origin request blocked", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// isSafeMethod reports whether a method is read-only by definition, and so
// exempt from the origin check. The mutating routes only accept POST, so
// this and the router's method patterns cover the same ground twice on
// purpose.
func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// authorize checks the access token, accepting it from the session cookie or
// from the ?t= parameter in the URL hostveil printed. A request that arrives
// with a valid parameter is given the cookie, so the dashboard's own fetches
// — which carry no query string — are authorized from then on.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	if s.token == "" {
		return true // no token configured; only reachable in tests
	}
	if c, err := r.Cookie(sessionCookie); err == nil && tokenEqual(c.Value, s.token) {
		return true
	}
	if !tokenEqual(r.URL.Query().Get("t"), s.token) {
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    s.token,
		Path:     "/",
		HttpOnly: true,
		// Strict, not Lax: Lax would send the cookie on a top-level
		// navigation from another site, which is exactly the CSRF shape the
		// origin check below exists to stop.
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

// tokenEqual compares in constant time so a wrong token cannot be recovered
// by timing the rejection.
func tokenEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
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
//
// Sec-Fetch-Site is consulted first because it is the browser's own account
// of where the request came from, and unlike Origin it is present on every
// request a modern browser makes. Its absence therefore means a non-browser
// client — curl, a script — which cannot be steered by a hostile web page
// and is the case the Origin/Referer fallback below is written for.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "cross-site", "same-site":
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		return hostFromURL(origin) == r.Host
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return hostFromURL(ref) == r.Host
	}
	// Neither header: not a browser request. It still had to present the
	// access token to reach this point, which a cross-origin page cannot
	// read, so this is the local-curl case rather than an open door.
	return true
}

// hostFromURL returns the host:port of a URL, or "" if it cannot be parsed.
//
// Hand-rolled prefix trimming was doing this, which credits the wrong host
// for anything the URL grammar allows and it does not — "http://evil.com\@"
// forms, userinfo, uppercase schemes. Comparing hosts is a security decision,
// so it uses the parser rather than an approximation of one.
func hostFromURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Host
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

// URL returns the dashboard URL to open, including the access token.
//
// The token has to travel somehow, and the URL is the one channel a user is
// already going to copy. On first load the server swaps it for a session
// cookie, so it is not needed again and does not reappear in any link the
// page itself generates.
//
// A wildcard bind is rendered as 127.0.0.1, because a wildcard is an
// instruction to the listener and not an address anyone can browse to —
// "http://0.0.0.0:8787/" pasted into a browser is at best confusing. It is
// also the address that actually works: the Host allowlist requires a
// loopback host regardless of what the socket is bound to.
func (s *Server) URL() string {
	return fmt.Sprintf("http://%s/?t=%s", browseHost(s.addr), s.token)
}

// browseHost turns a bind address into one a browser can use.
func browseHost(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}
