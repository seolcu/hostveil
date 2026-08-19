// Package web is hostveil's thin, localhost-bound web dashboard. Handlers
// marshal to/from core.Engine and nothing else — there is no detection,
// fix, scoring, or rollback logic here. It imports only core and model.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	// layout is the arrangement the page starts in, resolved the same way and
	// overridden the same way: the browser's own picker stores a choice in
	// localStorage and that wins for that browser.
	//
	// It is served rather than compiled in for the reason the theme is. The
	// dashboard had no way to be started in an arrangement at all — the only
	// route to one was the picker, so `hostveil serve` in a kiosk, a
	// screenshot script or a systemd unit always opened on the shipped
	// default and had to be clicked.
	layout string
	// token gates every route. See newToken for why loopback alone is not
	// enough of a boundary here.
	token string
	// progress is the per-domain snapshot behind GET /api/rescan/status.
	progress progressTracker
	// baseCtx is what a background rescan runs under: it must outlive the
	// request that started it (a closed tab is not an instruction to stop
	// scanning) but die with the server (Ctrl-C is). Set by ListenAndServe;
	// nil means Background, which only happens in tests.
	baseCtx context.Context
}

// Opts is what the dashboard is told before it starts, beyond the engine and
// the address.
//
// It is a struct because the two IDs are adjacent same-typed strings and
// transposing them fails silently in the worst available way: layoutJS and
// theme.CSS both fall back to their registry's default for an ID they do not
// recognise — deliberately, so a caller may pass whatever it has — so
// `--theme gruvbox --layout lanes` handed over the wrong way round produces
// the shipped theme and the shipped arrangement, with nothing logged and
// nothing on screen to say the flags were read at all.
//
// internal/ui/tui/tui.go's Opts states the same rule and gives the same
// reason. The dashboard was the caller that had not been brought to it.
type Opts struct {
	// Theme and Layout are IDs, resolved from --theme/--layout, the
	// environment, or the remembered choice. An unknown or empty one falls
	// back to that registry's default.
	Theme  string
	Layout string
}

// New builds a web Server bound to addr (e.g. "127.0.0.1:8787").
func New(engine *core.Engine, addr string, opts Opts) *Server {
	return &Server{engine: engine, addr: addr, theme: opts.Theme, layout: opts.Layout, token: newToken()}
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
	// Same arrangement, one layer down: every enum the page has to read —
	// domains, severities, remediation kinds, scan states, score bands —
	// comes from internal/model rather than from copies kept in app.js.
	mux.HandleFunc("GET /model.js", s.handleModelJS)
	// The layout picker, on the same pattern for the same reason: a blocking
	// script in <head> that restores the choice before first paint. See
	// layout.go — it is scaffolding for choosing an arrangement, not a
	// setting the dashboard means to keep.
	mux.HandleFunc("GET /layout.js", s.handleLayoutJS)
	mux.HandleFunc("GET /api/result", s.handleResult)
	mux.HandleFunc("GET /api/preview", s.handlePreview)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("GET /api/trend", s.handleTrend)
	mux.HandleFunc("GET /api/rescan/status", s.handleRescanStatus)
	mux.HandleFunc("GET /api/explain", s.handleExplain)
	mux.HandleFunc("POST /api/fix", s.handleFix)
	mux.HandleFunc("POST /api/fix/all", s.handleFixAll)
	mux.HandleFunc("POST /api/fix/batch", s.handleFixBatch)
	mux.HandleFunc("POST /api/rescan", s.handleRescan)
	mux.HandleFunc("POST /api/rollback", s.handleRollback)
	return s.guard(mux)
}

// shutdownGrace bounds how long a shutdown waits for in-flight requests. A
// fix or a rescan can legitimately be mid-flight, and cutting one off at the
// socket tells the browser nothing; a few seconds is enough for a handler
// that is nearly done and short enough that Ctrl-C still feels like Ctrl-C.
const shutdownGrace = 5 * time.Second

// ListenAndServe opens the listener immediately and serves the dashboard
// until ctx is cancelled, at which point it stops accepting and drains
// in-flight requests. The first scan runs the same way a rescan does — as a
// tracked background scan behind s.progress — rather than blocking here.
//
// It used to run the initial scan synchronously before opening the
// listener, on a host with many Docker images that is minutes during which
// the printed URL connects to nothing at all. The dashboard already had
// everything needed to show a scan in progress instead — POST /api/rescan,
// s.progress, and the frontend's own polling loop — the first scan simply
// never used any of it, so the operator's first look at hostveil was a
// browser tab that appeared to hang.
//
// The context is the whole point of the signature. Before it, serve ignored
// cancellation entirely: `cmdServe` took a context and never looked at it,
// and this method blocked in http.Server.ListenAndServe with no Shutdown
// wired up. Combined with signal.NotifyContext consuming the only signal it
// would ever act on, that left a root-owned dashboard which answered neither
// Ctrl-C nor `systemctl stop` and died only when systemd escalated to
// SIGKILL — mid-fix, if that is what it happened to be doing.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Background scans derive from this context, not from the requests that
	// start them. Set before the listener opens, so no handler can observe
	// it half-initialized.
	s.baseCtx = ctx

	if err := ctx.Err(); err != nil {
		return nil // interrupted before the listener would ever open
	}

	// Same sequence handleRescan uses: mark a scan running, then let it feed
	// s.progress in the background. begin() cannot answer false here — this
	// is the first scan there has ever been a chance to start — so unlike
	// handleRescan there is nothing to do with the return value.
	s.progress.begin()
	//nolint:gosec // G118: runTrackedScan reads s.baseCtx, set to ctx two lines
	// up, rather than taking a context argument — deliberately, since it also
	// runs from handleRescan, where the request's own context must not be the
	// one a scan runs under (see hostWork). gosec does not flag that call site
	// only because handleRescan's signature has no context.Context parameter
	// of its own for the heuristic to compare against; the pattern is the same.
	go s.runTrackedScan()

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		// No WriteTimeout: a rescan legitimately takes minutes on a host with
		// many images, and cutting the response off mid-scan would look like a
		// crash. IdleTimeout still reaps connections nobody is using.
		IdleTimeout: 2 * time.Minute,
	}

	idle := make(chan struct{})
	go func() {
		<-ctx.Done()
		grace, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		_ = srv.Shutdown(grace)
		close(idle)
	}()

	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		<-idle // let the drain finish before the process exits
		return nil
	}
	return err
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
			http.Error(w, "missing or invalid access token — open the URL Hostveil printed at startup",
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
	// Secure is deliberately unset, which is what gosec's G124 sees. The
	// dashboard is plain HTTP on loopback and cannot be anything else — it
	// has no certificate and no name to put on one — so a Secure cookie
	// would simply never be sent and every request would arrive
	// unauthenticated. HttpOnly and SameSite=Strict are both set, and the
	// transport is a socket on this machine that never reaches a network.
	//nolint:gosec // G124: loopback HTTP has no TLS for Secure to require
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
//
// The port has to be checked, not just discarded. net.SplitHostPort splits at
// the last colon and never asks whether what follows is a number, so
// "127.0.0.1:8787.evil.example.com" parses as host 127.0.0.1 with the
// attacker's domain as its port — and returned the loopback host this
// allowlist is written to trust. That is the same authority the Origin check
// already refuses; hostFromURL was moved onto net/url for exactly this reason
// and this function was left comparing an approximation. No browser will emit
// it, since a non-numeric port makes the URL unparseable, so nothing here was
// reachable through the rebinding attack the allowlist defends against — but
// a host check that credits the wrong host is not worth reasoning about twice.
//
// An authority with no port carries an IPv6 literal in brackets, which
// SplitHostPort strips only when it succeeds. Without stripping them here,
// http://[::1]/ is refused by the very list that names ::1.
func hostAllowed(host string) bool {
	h, port, err := net.SplitHostPort(host)
	switch {
	case err != nil:
		h = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	case !isNumericPort(port):
		return false
	}
	switch h {
	case "127.0.0.1", "::1", "localhost", "":
		return true
	default:
		return false
	}
}

// isNumericPort reports whether p is a port number and nothing else. An empty
// port is the "host:" form, which addresses the default port rather than a
// name of the attacker's choosing.
func isNumericPort(p string) bool {
	if p == "" {
		return true
	}
	_, err := strconv.ParseUint(p, 10, 16)
	return err == nil
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
	serveGenerated(w, "text/css; charset=utf-8", theme.CSS(s.theme))
}

func (s *Server) handleThemeJS(w http.ResponseWriter, _ *http.Request) {
	serveGenerated(w, "text/javascript; charset=utf-8", theme.JS(s.theme))
}

func (s *Server) handleLayoutJS(w http.ResponseWriter, _ *http.Request) {
	serveGenerated(w, "text/javascript; charset=utf-8", layoutJS(s.layout))
}

func (s *Server) handleModelJS(w http.ResponseWriter, _ *http.Request) {
	serveGenerated(w, "text/javascript; charset=utf-8", modelJS())
}

// serveGenerated writes an asset this process generated for this run, rather
// than one shipped in the binary.
//
// It exists for the Cache-Control line. What these routes serve depends on
// flags resolved at startup — the palette on --theme, the arrangement on
// --layout — so a browser that cached one would keep the previous run's
// appearance and there is nothing in the URL to tell it apart. The four
// handlers each set it by hand, which made it something a fifth route could
// omit with no test and no symptom until somebody restarted with a different
// flag and got the old look.
func serveGenerated(w http.ResponseWriter, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, body)
}

// resultPayload is the dashboard's view of a scan: the report, plus how it
// differs from the one before it. The engine already computes the delta on
// every scan; without this the dashboard would throw away the one thing
// that tells an operator whether their last round of fixes helped. Report
// is embedded so its JSON stays flat and the shape only gains a field.
//
// HasRun is what tells a never-scanned report apart from a scan that found
// nothing — both have Findings: null. Read it whenever Findings is empty
// and rendering depends on which of the two it is.
type resultPayload struct {
	model.Report
	Delta  model.Delta `json:"delta"`
	HasRun bool        `json:"hasRun"`
}

// handleTrend serves the score of every retained scan, plus the sparkline
// the TUI draws from the same points.
//
// The glyphs come from model.Sparkline rather than being bucketed again in
// JavaScript: two implementations of one rule is the shape that has already
// gone wrong twice here — the severity palette before internal/ui/theme,
// the domain table before /model.js.
//
// It is its own route rather than a field on /api/result because the result
// is refetched after every fix, and re-reading thirty snapshots from disk
// each time would be work nobody asked for. The trend only moves when a
// scan does.
func (s *Server) handleTrend(w http.ResponseWriter, _ *http.Request) {
	points, err := s.engine.ScoreHistory()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, struct {
		Points    []model.ScorePoint `json:"points"`
		Sparkline string             `json:"sparkline"`
	}{Points: points, Sparkline: model.Sparkline(points)})
}

func (s *Server) handleResult(w http.ResponseWriter, _ *http.Request) {
	report, hasRun := s.engine.Current()
	writeJSON(w, resultPayload{Report: report, Delta: s.engine.LastDelta(), HasRun: hasRun})
}

// hostWork returns the context a host-mutating or host-scanning operation
// should run under: the request's values, but not its cancellation.
//
// net/http cancels a request context as soon as the client disconnects, and a
// browser disconnects for reasons that have nothing to do with intent —
// closing the tab, navigating away, a laptop lid. Letting that cancel the
// work is wrong in both directions here. A rescan cut off part-way leaves a
// report whose domains are empty because they were killed, and a fix cut off
// part-way is a half-applied change to the host. Neither is what the person
// closing a tab asked for.
//
// The work is already bounded without the request: every command carries
// platform.DefaultTimeout, and the engine serialises apply and scan behind
// one mutex, so this cannot accumulate runaway work.
func hostWork(r *http.Request) context.Context {
	return context.WithoutCancel(r.Context())
}

// handleRescan starts a scan in the background and returns immediately —
// a rescan takes minutes on a real host, and a response that blocks for
// the duration gives the browser nothing to render but a frozen button.
// The client polls /api/rescan/status and fetches /api/result when the
// running flag drops.
//
// The scan runs under the server's base context rather than the request's:
// a closed tab must not abort a scan (the hostWork rule), but Ctrl-C on the
// server should.
func (s *Server) handleRescan(w http.ResponseWriter, _ *http.Request) {
	if !s.progress.begin() {
		http.Error(w, "a scan is already running", http.StatusConflict)
		return
	}
	go s.runTrackedScan()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("{\"started\":true}\n"))
}

// scanEventBuffer sizes the progress channel. The engine drops events on a
// full buffer rather than stall a checker; a generous buffer plus a
// dedicated drain goroutine makes that a non-event.
const scanEventBuffer = 64

// runTrackedScan runs one scan, feeding the progress tracker until the
// engine is done and every event has been drained.
func (s *Server) runTrackedScan() {
	events := make(chan model.ScanEvent, scanEventBuffer)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for ev := range events {
			s.progress.update(ev)
		}
	}()

	ctx := s.baseCtx
	if ctx == nil {
		ctx = context.Background()
	}
	s.engine.Scan(ctx, events)
	close(events)
	<-drained
	s.progress.finish()
}

func (s *Server) handleRescanStatus(w http.ResponseWriter, _ *http.Request) {
	// Never cache: the whole point of the route is that the answer changes
	// second to second.
	w.Header().Set("Cache-Control", "no-store")
	running, domains := s.progress.snapshot()
	writeJSON(w, struct {
		Running bool              `json:"running"`
		Domains []model.ScanEvent `json:"domains"`
	}{running, domains})
}

// handleExplain returns the deterministic explanation plus, when a local
// AI provider is reachable, an advisory AI one (model.Explanation's ai /
// ai_error fields). It runs under the request's own context, unlike a fix
// or a scan: an explanation mutates nothing, so one nobody is waiting for
// should die with the tab that asked for it.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	f, ok := s.lookup(r.URL.Query().Get("id"), r.URL.Query().Get("service"))
	if !ok {
		http.Error(w, "no such finding", http.StatusNotFound)
		return
	}
	writeJSON(w, s.engine.Explain(r.Context(), f, true))
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
	outcome, err := s.engine.ApplyFix(hostWork(r), f, req.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, outcome)
}

func (s *Server) handleFixAll(w http.ResponseWriter, r *http.Request) {
	report, _ := s.engine.Current()
	// The whole report, which is what the dashboard's button counts: its
	// filter chips narrow the list, not the batch. The TUI means the other
	// thing by the same words, and saying so through one helper is how the
	// two stay deliberately different rather than accidentally so.
	writeJSON(w, s.engine.ApplyBatch(hostWork(r), report.AutoFixable(model.Filter{})))
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
	writeJSON(w, s.engine.ApplyBatch(hostWork(r), sel))
}

func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	cps, err := s.engine.ListCheckpoints()
	// Unreadable checkpoints leave a usable list behind, so the dashboard
	// still renders it and carries the warning alongside rather than replacing
	// the whole history view with a 500.
	if err != nil && !core.IsIncompleteHistory(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	payload := struct {
		Checkpoints []model.Checkpoint `json:"checkpoints"`
		Warning     string             `json:"warning,omitempty"`
	}{Checkpoints: cps}
	if err != nil {
		payload.Warning = err.Error()
	}
	writeJSON(w, payload)
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
	// Active, not !Fixed: a pending finding is still on the page, so Explain
	// and Preview have to resolve it or the two buttons 404 on a visible row.
	for _, f := range report.Findings {
		if !f.Active() || f.ID != id {
			continue
		}
		if service == "" || f.Service == service {
			return f, true
		}
	}
	return model.Finding{}, false
}

// writeJSON encodes v as the response body.
//
// Encoding into a buffer first is what makes a failure reportable. Streaming
// straight into the ResponseWriter commits the 200 and the headers with the
// first byte, so an error partway leaves the client holding truncated JSON
// under a success status — which reads as a parse bug on their side rather
// than a failure on ours.
func writeJSON(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, "cannot encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
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
