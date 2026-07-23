package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/theme"
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
	switch {
	case name == "docker" && strings.Join(args, " ") == "compose ls --all --format json":
		return []byte(f.lsJSON), nil
	// Checkers probe the daemon before trusting the CLI's presence.
	case name == "docker" && strings.Join(args, " ") == "version --format {{.Server.Version}}":
		return []byte("27.0.3\n"), nil
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
	return New(engine, "127.0.0.1:0", "nord"), path
}

// authedClient returns a client carrying the dashboard's access token in its
// cookie jar, which is the state a browser is in after following the URL
// hostveil prints. Requests without it are rejected before routing, so every
// test that exercises a route needs this rather than http.DefaultClient.
func authedClient(t *testing.T, s *Server, srv *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: s.token}})
	return &http.Client{Jar: jar}
}

// authed adds the access token to a request built with httptest.NewRequest,
// which does not go through a cookie jar.
func authed(s *Server, r *http.Request) *http.Request {
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.token})
	return r
}

func TestResultEndpoint(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := authedClient(t, s, srv).Get(srv.URL + "/api/result")
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
	req := authed(s, httptest.NewRequest(http.MethodPost, "/api/rescan", nil))
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
	resp, err := authedClient(t, s, srv).Do(req)
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
	resp, err := authedClient(t, s, srv).Do(req)
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

	client := authedClient(t, s, srv)
	post := func(p, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+p, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", srv.URL)
		resp, err := client.Do(req)
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
	histResp, err := client.Get(srv.URL + "/api/history")
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
	resResp, err := client.Get(srv.URL + "/api/result")
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
	req := authed(s, httptest.NewRequest(http.MethodPost, "/api/rollback",
		strings.NewReader(`{"checkpoint_id":"nope"}`)))
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
	resp, err := authedClient(t, s, srv).Get(srv.URL + "/")
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

// TestResultCarriesDelta: the dashboard has to be able to answer "did my
// last round of fixes help?", which means the engine's delta must survive
// the trip through the API rather than being dropped as it used to be.
func TestResultCarriesDelta(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	for _, path := range []string{"/api/result", "/api/rescan"} {
		var payload struct {
			Findings []model.Finding `json:"findings"`
			Delta    *model.Delta    `json:"delta"`
		}
		var resp *http.Response
		var err error
		client := authedClient(t, s, srv)
		if path == "/api/rescan" {
			resp, err = client.Post(srv.URL+path, "application/json", nil)
		} else {
			resp, err = client.Get(srv.URL + path)
		}
		if err != nil {
			t.Fatal(err)
		}
		err = json.NewDecoder(resp.Body).Decode(&payload)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if payload.Delta == nil {
			t.Errorf("%s: response carries no delta field", path)
		}
		// Embedding must not have disturbed the existing flat shape.
		if len(payload.Findings) == 0 {
			t.Errorf("%s: findings disappeared from the payload", path)
		}
	}
}

// The dashboard's palette is generated from internal/ui/theme rather than
// shipped in app.css, so that it and the TUI cannot drift. That only holds if
// the two generated routes actually serve.
func TestThemeAssets(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	for _, tc := range []struct{ path, ctype string }{
		{"/themes.css", "text/css"},
		{"/theme.js", "text/javascript"},
	} {
		resp, err := authedClient(t, s, srv).Get(srv.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s returned %d", tc.path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, tc.ctype) {
			t.Errorf("%s Content-Type = %q, want %s", tc.path, ct, tc.ctype)
		}
		for _, th := range theme.All() {
			if !strings.Contains(string(body), th.ID) {
				t.Errorf("%s does not mention theme %q", tc.path, th.ID)
			}
		}
	}
}

// The page paints in the theme hostveil was started with, before any script
// runs — otherwise every load flashes the default palette first.
func TestServedThemeIsTheStartingPalette(t *testing.T) {
	s, _ := testServer(t) // built with "nord"
	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodGet, "/themes.css", nil))
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/themes.css returned %d", rec.Code)
	}

	nord, ok := theme.Lookup("nord")
	if !ok {
		t.Fatal("the nord theme is gone")
	}
	css := rec.Body.String()
	start, end := strings.Index(css, ":root {"), strings.Index(css, ":root[data-theme=")
	if start < 0 || end < start {
		t.Fatalf("no bare :root block in the stylesheet:\n%s", css)
	}
	if root := css[start:end]; !strings.Contains(root, nord.Palette.Ink) {
		t.Errorf(":root is not the served theme's palette:\n%s", root)
	}
}

// Generated routes are inside the same guard as everything else; a page that
// could be styled cross-origin is a page that can be framed convincingly.
func TestThemeAssetsAreGuarded(t *testing.T) {
	s, _ := testServer(t)
	for _, path := range []string{"/themes.css", "/theme.js"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "evil.example.com"
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s from a forbidden host returned %d", path, rec.Code)
		}
	}
}

// Moving the palette out of app.css and into a generated stylesheet means the
// two files now have to agree: every var(--x) the layout reads must be one the
// theme package declares. A typo, or a variable added to app.css and never to
// a palette, resolves to nothing — and an unset custom property is not an
// error in CSS, it is an invisible element.
func TestEveryCSSVariableIsDeclared(t *testing.T) {
	appCSS, err := assets.ReadFile("assets/app.css")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`(--[a-z0-9-]+):`).FindAllStringSubmatch(theme.CSS("")+string(appCSS), -1) {
		declared[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`var\((--[a-z0-9-]+)`).FindAllStringSubmatch(string(appCSS), -1) {
		if !declared[m[1]] {
			t.Errorf("app.css reads %s, which no palette declares", m[1])
		}
	}
}

// The page has to actually load the generated files. app.css deliberately no
// longer carries a palette, so an index.html that drops either link renders
// the dashboard with no colors at all.
func TestIndexLoadsTheGeneratedThemeAssets(t *testing.T) {
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	for _, want := range []string{`href="/themes.css"`, `src="/theme.js"`} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html does not load %s", want)
		}
	}
	// theme.js restores the saved theme and must run before the first paint;
	// below the stylesheet links it would apply a palette the page has
	// already been drawn without.
	if strings.Index(html, `href="/themes.css"`) > strings.Index(html, `src="/theme.js"`) {
		t.Error("theme.js is loaded before themes.css, so the page can paint unstyled first")
	}
	if !strings.Contains(html, `<select id="theme"`) {
		t.Error("the status bar has no theme picker")
	}
}

// TestMutatingRoutesRejectGET is the regression guard for a live CSRF hole.
//
// The guard checked the origin of POSTs only, and the handlers ignored the
// request method entirely. A GET therefore skipped the origin check and still
// reached the handler, so `<img src="http://127.0.0.1:8787/api/fix/all">` on
// any page in the world made the dashboard apply every Auto fix on the host —
// verified applying three real fixes to a compose file before this landed. An
// <img> cannot carry the access token either, but the method restriction is
// what makes the route unreachable rather than merely unauthorized.
func TestMutatingRoutesRejectGET(t *testing.T) {
	s, path := testServer(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, route := range []string{"/api/fix", "/api/fix/all", "/api/fix/batch", "/api/rescan", "/api/rollback"} {
		rec := httptest.NewRecorder()
		req := authed(s, httptest.NewRequest(http.MethodGet, route, nil))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Origin", "http://evil.example.com")
		s.Handler().ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Errorf("GET %s succeeded (%d) — a cross-origin <img> can reach it", route, rec.Code)
		}
	}

	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("cross-origin GETs modified the host's compose file:\n%s", after)
	}
}

// The token is the boundary between the operator and every other account on
// the machine. hostveil auto-elevates for `serve`, so an unauthenticated
// route is root applying fixes on behalf of whoever asked.
func TestRoutesRequireTheAccessToken(t *testing.T) {
	s, _ := testServer(t)
	for _, route := range []string{"/", "/api/result", "/api/history", "/themes.css", "/api/fix/all"} {
		rec := httptest.NewRecorder()
		method := http.MethodGet
		if route == "/api/fix/all" {
			method = http.MethodPost
		}
		req := httptest.NewRequest(method, route, nil) // deliberately no token
		req.Host = "127.0.0.1:8787"
		s.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token returned %d, want 401", method, route, rec.Code)
		}
	}
}

// A wrong token must not be accepted, and must not be distinguishable from
// any other wrong token.
func TestWrongTokenIsRejected(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/result?t="+strings.Repeat("a", 64), nil)
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a wrong token returned %d, want 401", rec.Code)
	}
}

// The token travels in the URL once and is exchanged for a session cookie,
// so the dashboard's own fetches — which carry no query string — stay
// authorized without the token reappearing in every request.
func TestTokenInURLSetsTheSessionCookie(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/result?t="+s.token, nil)
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a valid token in the URL returned %d", rec.Code)
	}
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie was set")
	}
	if !session.HttpOnly {
		t.Error("the session cookie must be HttpOnly — a script should not be able to read the token")
	}
	if session.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie must be SameSite=Strict; Lax would ride along on a cross-site navigation")
	}
}

// The printed URL has to be the one that works, or the token is a puzzle
// rather than a credential.
func TestURLCarriesTheToken(t *testing.T) {
	s, _ := testServer(t)
	if !strings.Contains(s.URL(), "t="+s.token) {
		t.Errorf("URL() = %q, which does not carry the access token", s.URL())
	}
}

// Origin comparison decides whether a request may mutate the host, so it
// parses the URL rather than trimming a prefix off it. The old hand-rolled
// version credited the host of anything that merely started with the right
// characters.
func TestOriginMatchingIsNotPrefixBased(t *testing.T) {
	s, _ := testServer(t)
	for _, origin := range []string{
		"http://127.0.0.1:8787.evil.example.com",
		"http://evil.example.com/127.0.0.1:8787",
		"http://user@evil.example.com",
	} {
		rec := httptest.NewRecorder()
		req := authed(s, httptest.NewRequest(http.MethodPost, "/api/rescan", nil))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Origin", origin)
		s.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Origin %q returned %d, want 403", origin, rec.Code)
		}
	}
}

// A browser labels every request it makes. When it says the request came
// from another site, that settles it regardless of the other headers.
func TestSecFetchSiteBlocksCrossSite(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodPost, "/api/rescan", nil))
	req.Host = "127.0.0.1:8787"
	req.Header.Set("Origin", "http://127.0.0.1:8787") // spoof-friendly header agrees
	req.Header.Set("Sec-Fetch-Site", "cross-site")    // the browser's own account does not
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a cross-site labelled request returned %d, want 403", rec.Code)
	}
}

// A wildcard bind is an instruction to the listener, not an address anyone
// can browse to — and the Host allowlist requires a loopback name whatever
// the socket is bound to. The Vagrant demo binds 0.0.0.0 and reaches the
// dashboard through a port-forward, so the URL it prints has to be usable.
func TestURLRendersAWildcardBindAsLoopback(t *testing.T) {
	s, _ := testServer(t)
	for _, tc := range []struct{ addr, want string }{
		{"0.0.0.0:8787", "http://127.0.0.1:8787/"},
		{":8787", "http://127.0.0.1:8787/"},
		{"[::]:8787", "http://127.0.0.1:8787/"},
		{"127.0.0.1:8787", "http://127.0.0.1:8787/"},
	} {
		s.addr = tc.addr
		if got := s.URL(); !strings.HasPrefix(got, tc.want+"?t=") {
			t.Errorf("addr %q → URL %q, want it to start with %q", tc.addr, got, tc.want)
		}
	}
}
