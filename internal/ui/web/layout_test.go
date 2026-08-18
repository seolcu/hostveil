package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The picker exists to settle which arrangement hostveil keeps, so what
// these tests hold is the property that makes it usable for that: every
// entry in it must actually do something, and choosing none of them must
// leave the shipped dashboard exactly as it was.

// An option in the picker that no stylesheet rule answers is a dead entry:
// the operator selects it, the page does not move, and the arrangement gets
// judged on the one it was already looking at.
//
// One arrangement is exempt, and it is not the default. app.css draws A ·
// Split with its base rules and every other arrangement is a layer of
// overrides on top of them — including C · Console, which is what an operator
// gets. That split rather than the default is the ground is deliberate: it is
// what a browser falls back to if layout.js never runs, and a page with no
// rail is the safer of the two failure modes, since the rail is a column the
// base grid has not reserved room for.
const baseArrangement = "split"

func TestEveryLayoutIsAnsweredByTheStylesheet(t *testing.T) {
	css := readAsset(t, "assets/app.css")
	for _, l := range Layouts() {
		if l.ID == baseArrangement {
			continue
		}
		if !strings.Contains(css, `[data-layout="`+l.ID+`"]`) {
			t.Errorf("layout %q is in the picker but no rule in app.css answers it, "+
				"so choosing it changes nothing", l.ID)
		}
	}
}

// The reverse: a stylesheet rule for a layout nobody can select is dead CSS
// that the next person has to work out the status of.
func TestNoStylesheetRuleForAnUnregisteredLayout(t *testing.T) {
	css := readAsset(t, "assets/app.css")
	known := map[string]bool{}
	for _, l := range Layouts() {
		known[l.ID] = true
	}
	for _, m := range regexp.MustCompile(`\[data-layout="([^"]+)"\]`).FindAllStringSubmatch(css, -1) {
		if !known[m[1]] {
			t.Errorf("app.css styles data-layout=%q, which is not a registered layout", m[1])
		}
	}
}

// An operator who never opens the picker must see the arrangement hostveil
// chose, not whichever one happened to be listed first. Named rather than
// read back from DefaultLayout, which would agree with itself.
func TestDefaultLayoutIsTheChosenArrangement(t *testing.T) {
	if got := DefaultLayout().ID; got != "console" {
		t.Errorf("DefaultLayout = %q, want the rail arrangement", got)
	}
	if Layouts()[0].ID != DefaultLayout().ID {
		t.Error("the default is not first in the picker, so the list does not lead with what an operator gets")
	}
	if !strings.Contains(readAsset(t, "assets/app.css"), `[data-layout="console"]`) {
		t.Error("the default arrangement has no rules in app.css, so an operator who never opens the picker gets the base ones")
	}
}

func TestRailLayoutsRestoreAxesWhenTheRailCollapses(t *testing.T) {
	css := readAppCSS(t)
	want := `:root[data-layout="console"] .axes,
  :root[data-layout="railverdict"] .axes { display: grid; }`
	if !strings.Contains(css, want) {
		t.Fatal("the phone breakpoint hides the domain rail, so Console and Rail + verdict must restore the axes strip")
	}
}

// The IDs go on <html data-layout> and into a CSS attribute selector and a
// localStorage key, so they have to stay slug-shaped and distinct.
func TestLayoutIDsAreUniqueSlugs(t *testing.T) {
	slug := regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	seen := map[string]bool{}
	for _, l := range Layouts() {
		if !slug.MatchString(l.ID) {
			t.Errorf("layout ID %q is not a plain slug", l.ID)
		}
		if seen[l.ID] {
			t.Errorf("duplicate layout ID %q", l.ID)
		}
		seen[l.ID] = true
		if l.Name == "" || l.Note == "" {
			t.Errorf("layout %q has an empty name or note; the picker is being used to "+
				"decide, so an unlabelled option is not a choice", l.ID)
		}
	}
}

// The generated script has to carry the whole registry and the default, and
// it has to apply the choice itself — app.js reads data-layout rather than
// setting it, so a script that only declared the list would leave every
// browser on an unset attribute.
func TestLayoutJSCarriesTheRegistryAndApplies(t *testing.T) {
	js := layoutJS("")
	for _, l := range Layouts() {
		if !strings.Contains(js, `"`+l.ID+`"`) {
			t.Errorf("/layout.js does not carry layout %q", l.ID)
		}
		if !strings.Contains(js, l.Name) {
			t.Errorf("/layout.js does not carry the name of %q", l.ID)
		}
	}
	for _, want := range []string{
		"window.HOSTVEIL_LAYOUTS",
		`window.HOSTVEIL_LAYOUT_DEFAULT = "` + DefaultLayout().ID + `"`,
		`localStorage.getItem("hostveil.layout")`,
		`setAttribute("data-layout"`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("/layout.js is missing %s", want)
		}
	}
	// Private mode makes localStorage throw on read. Unguarded, that would
	// abort a blocking <head> script and take app.js's tables down with it.
	if !strings.Contains(js, "catch (e)") {
		t.Error("/layout.js reads localStorage without a guard; private mode would abort the page")
	}
}

func TestLookupLayout(t *testing.T) {
	if _, ok := LookupLayout("lanes"); !ok {
		t.Error(`LookupLayout("lanes") missed a registered layout`)
	}
	if _, ok := LookupLayout("nope"); ok {
		t.Error(`LookupLayout("nope") resolved an unregistered layout`)
	}
}

// The route has to serve, and — like every other generated asset — from
// inside the guard. A stylesheet-shaped route reachable cross-origin is a
// route that can be used to fingerprint the dashboard.
func TestLayoutJSRoute(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := authedClient(t, s, srv).Get(srv.URL + "/layout.js")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/layout.js returned %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("/layout.js Content-Type = %q", ct)
	}
	if !strings.Contains(string(body), "HOSTVEIL_LAYOUTS") {
		t.Error("/layout.js did not serve the registry")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/layout.js", nil)
	req.Host = "evil.example.com"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("/layout.js from a forbidden host returned %d", rec.Code)
	}
}

// The restore has to happen before the first paint, for a stronger reason
// than the theme's: switching a palette after paint is a flash, but
// switching to the rail arrangement after paint is the page visibly
// rebuilding itself in front of the reader.
func TestIndexLoadsLayoutJSBlockingAndBeforeAppJS(t *testing.T) {
	html := readAsset(t, "assets/index.html")
	i := strings.Index(html, `src="/layout.js"`)
	if i < 0 {
		t.Fatal("index.html never loads /layout.js")
	}
	if strings.Contains(html[i:strings.Index(html, "</head>")], "defer") ||
		strings.Contains(html[i:strings.Index(html, "</head>")], "async") {
		t.Error("/layout.js is deferred, so the page paints in the shipped layout and then jumps")
	}
	if i > strings.Index(html, "</head>") {
		t.Error("/layout.js is outside <head>, so the body paints before the layout is applied")
	}
	if i > strings.Index(html, `src="/app.js"`) {
		t.Error("/layout.js loads after app.js, which reads data-layout on its first render")
	}
}

// The DOM the alternatives need has to be in the page for all of them: the
// verdict band, the rail, the scrim and the one detail node are shared, and
// a layout whose region is missing degrades into a blank area rather than
// into the arrangement it is meant to be.
func TestIndexCarriesTheSharedRegions(t *testing.T) {
	html := readAsset(t, "assets/index.html")
	for _, id := range []string{`id="verdict"`, `id="rail"`, `id="scrim"`, `id="detail"`, `id="layout"`} {
		if !strings.Contains(html, id) {
			t.Errorf("index.html is missing %s", id)
		}
	}
	// Exactly one detail node. Two would mean the preview, the AI box and the
	// close button each land in one of them, and only one is on screen.
	if n := strings.Count(html, `id="detail"`); n != 1 {
		t.Errorf("index.html declares %d detail nodes, want exactly 1", n)
	}
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := assets.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// The lane header's button hands its severity's Auto findings to the batch
// bar. It does not apply them — the batch bar does that, on its own click,
// after its own confirmation — so it must not say it fixes anything.
//
// It said "Fix the N safe", which is an action the button does not perform:
// clicking it ticks N checkboxes and stops. The terminal's `m` does exactly
// the same thing and has always described it as selecting, so this was also
// the two interfaces disagreeing about what one arrangement does.
func TestTheLaneButtonSaysItSelectsRatherThanFixes(t *testing.T) {
	js := readAsset(t, "assets/app.js")
	i := strings.Index(js, "function laneRows(")
	if i < 0 {
		t.Fatal("app.js no longer defines laneRows — this test needs to know")
	}
	body := js[i:]
	if j := strings.Index(body[1:], "\nfunction "); j >= 0 {
		body = body[:j]
	}
	label := regexp.MustCompile("`(Select|Fix) the \\$\\{autos\\.length\\} safe`")
	m := label.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the lane button's label is not where this test looks for it:\n%s", body)
	}
	if m[1] != "Select" {
		t.Errorf("the lane button says %q, but it only marks findings for the batch bar", m[0])
	}
	// And it must still be a marking button rather than a second route to the
	// apply endpoint: one path to that POST, not two.
	if strings.Contains(body, "fetch(") || strings.Contains(body, "/api/fix") {
		t.Error("laneRows posts to the API itself instead of going through the batch bar")
	}
}

// The served default is what `serve --layout` resolved to, so a browser with
// no stored choice opens in the arrangement the operator asked for. Before
// this the only route to an arrangement was the picker, so a kiosk, a
// screenshot script or a systemd unit always got the shipped one.
func TestLayoutJSServesTheRequestedStartArrangement(t *testing.T) {
	want := Layouts()[len(Layouts())-1].ID
	if want == DefaultLayout().ID {
		t.Fatal("the registry has one arrangement; this test needs two")
	}
	js := layoutJS(want)
	if !strings.Contains(js, `window.HOSTVEIL_LAYOUT_DEFAULT = "`+want+`"`) {
		t.Errorf("/layout.js does not open in %q", want)
	}
	// And an ID from a registry this build does not have must not reach the
	// page: the applier compares against the list and would leave the
	// attribute unset, which paints the base arrangement rather than any
	// registered one.
	for _, bad := range []string{"", "not-an-arrangement"} {
		js := layoutJS(bad)
		if !strings.Contains(js, `window.HOSTVEIL_LAYOUT_DEFAULT = "`+DefaultLayout().ID+`"`) {
			t.Errorf("layoutJS(%q) did not fall back to the shipped arrangement", bad)
		}
	}
}
