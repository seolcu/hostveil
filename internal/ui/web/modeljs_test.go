package web

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The dashboard turns a finding's numeric source into a filter chip and a
// domain-status line. It used to do that from a table written out by hand
// in app.js, and that table stopped at nine entries while model.Source grew
// to ten. The consequences were both silent: the chip list was built by
// looking each source up and discarding the misses, so the whole sysctl
// domain became unfilterable, and a failed sysctl domain rendered as
// "! 10 failed" — the integer, because there was nothing to name it with.
//
// Serving the table from model.AllSources is the fix; this is what keeps it
// fixed. It asserts the generated file names every domain, by number and by
// label, so a domain added without a Label() cannot reach the page as a
// bare integer again.
func TestGeneratedDomainsCoverEverySource(t *testing.T) {
	js := modelJS()
	for i, src := range model.AllSources() {
		// The whole entry, not its pieces. A domain present but nameless is
		// the failure mode that shipped: app.js falls back to String(s) and
		// draws the integer, which reads as a rendering glitch rather than
		// as a missing table entry.
		want := fmt.Sprintf("    %q: {id: %q, label: %q, rank: %d},", src.String(), src.String(), src.Label(), i)
		if src.Label() == "" {
			t.Errorf("%q (%d) reaches the dashboard with no label", src.String(), int(src))
			continue
		}
		if !strings.Contains(js, want) {
			t.Errorf("/model.js is missing %s", strings.TrimSpace(want))
		}
	}
	// Nothing-extracted guard: an empty generator would satisfy nothing
	// above if AllSources were also empty, and would pass silently.
	if n := strings.Count(js, "{id: "); n != len(model.AllSources()) {
		t.Fatalf("/model.js declares %d domain entries for %d domains", n, len(model.AllSources()))
	}
}

// Everything else the page mirrors. The domain table was generated first
// and alone, on the argument that the other enums were closed sets that
// could not drift; the axis-label table then drifted anyway. These assert
// the whole vocabulary reaches the browser, by value, so nothing has to be
// kept in step by hand.
func TestGeneratedModelCoversEveryEnum(t *testing.T) {
	js := modelJS()

	for i, s := range model.AllSeverities() {
		want := fmt.Sprintf("    %q: {name: %q, abbr: %q, rank: %d},", s.String(), s.String(), s.Abbr(), i)
		if !strings.Contains(js, want) {
			t.Errorf("/model.js is missing severity %s", strings.TrimSpace(want))
		}
	}
	for _, r := range model.AllRemediationKinds() {
		want := fmt.Sprintf("    %q: {name: %q, label: %q, fixable: %t, auto: %t},",
			r.String(), r.String(), r.Label(), r.IsFixable(), r == model.RemediationAuto)
		if !strings.Contains(js, want) {
			t.Errorf("/model.js is missing remediation %s", strings.TrimSpace(want))
		}
	}
	for _, s := range model.AllScanStates() {
		want := fmt.Sprintf("    %q: {name: %q, ran: %t, complete: %t},",
			s.String(), s.String(), s.Ran(), s.Complete())
		if !strings.Contains(js, want) {
			t.Errorf("/model.js is missing scan state %s", strings.TrimSpace(want))
		}
	}

	// Bands are emitted as an ordered list, best-first, because the page
	// resolves a score by taking the first floor it clears. Emitted in any
	// other order the walk silently returns the wrong band.
	var floors []int
	for _, b := range model.Bands() {
		want := fmt.Sprintf("    {name: %q, min: %d, cls: %q, verdict: %q},",
			b.String(), b.Min(), bandClass(b), b.Verdict())
		if !strings.Contains(js, want) {
			t.Errorf("/model.js is missing band %s", strings.TrimSpace(want))
		}
		floors = append(floors, int(b.Min()))
		// Every band needs a class and a phrase of its own, or two ranges
		// render alike.
		if bandClass(b) == "b-na" {
			t.Errorf("band %v has no meter class", b)
		}
		if b.Verdict() == "unscored" {
			t.Errorf("band %v has no verdict phrase", b)
		}
	}
	for i := 1; i < len(floors); i++ {
		if floors[i] >= floors[i-1] {
			t.Errorf("bands are not emitted best-first: floor %d follows %d", floors[i], floors[i-1])
		}
	}

	assertDistinctStrings(t, "band class", model.Bands(), bandClass)
	assertDistinctStrings(t, "band verdict", model.Bands(), model.Band.Verdict)

	// Nothing-extracted guards, one per table.
	for _, tc := range []struct {
		what string
		want int
	}{
		{"abbr:", len(model.AllSeverities())},
		{"fixable:", len(model.AllRemediationKinds())},
		{"complete:", len(model.AllScanStates())},
		{"verdict:", len(model.Bands())},
	} {
		if n := strings.Count(js, tc.what); n != tc.want {
			t.Errorf("/model.js declares %d %q entries, want %d", n, tc.what, tc.want)
		}
	}
}

func assertDistinctStrings[T comparable](t *testing.T, what string, vals []T, name func(T) string) {
	t.Helper()
	seen := map[string]T{}
	for _, v := range vals {
		n := name(v)
		if prev, dup := seen[n]; dup {
			t.Errorf("%s: %v and %v share %q", what, prev, v, n)
		}
		seen[n] = v
	}
}

// The table is only useful if the page can actually fetch it. It is a
// blocking script in <head>, so a 404 here is a dashboard that renders its
// domain chips as integers — the original bug, reintroduced through the
// routing table instead of the data.
func TestModelScriptIsServedAndReferenced(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := authedClient(t, s, srv).Get(srv.URL + "/model.js")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/model.js returned %d", resp.StatusCode)
	}
	// A script served as anything else is refused by the browser, and the
	// page then runs app.js against an undefined table.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("/model.js Content-Type = %q, want text/javascript", ct)
	}
	if !strings.Contains(string(body), "window.HOSTVEIL_MODEL") {
		t.Errorf("/model.js does not define window.HOSTVEIL_MODEL:\n%s", body)
	}

	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), `src="/model.js"`) {
		t.Error("index.html does not load /model.js")
	}
}

// Every table this replaced, spelled as it was spelled when it drifted.
//
// The domain table was generated and its copy in app.js deleted, and one
// guard was added for that one literal. A *second* label table — the axis
// short names — was sitting twenty lines away the whole time, and grew
// stale by two domains without tripping anything. So the guard covers each
// deleted table by its own shape: it is cheap, and the failure it catches
// is one that compiles, renders, and looks fine.
func TestAppJSHasNoMirroredTables(t *testing.T) {
	app, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(app)

	for _, tc := range []struct{ shape, what string }{
		{`1: "Container"`, "a domain table"},
		{`container: "Container"`, "an axis-label table"},
		// Built from the model rather than written out, because a literal
		// here is a guard keyed to one generation of the scale: these three
		// rows named the four-level names, so the table they had to catch
		// after the merge — the current three, in order — went straight
		// past them. A guard against a stale copy must not itself be one.
		{severityArrayLiteral(model.Severity.String), "a severity name table"},
		{severityArrayLiteral(model.Severity.Abbr), "a severity abbreviation table"},
		{`"Unclassified", "Auto-fix"`, "a remediation label table"},
		{`>= 80 ?`, "the score band thresholds"},
		{`SCAN_DONE = `, "the scan-state ordinals"},
		{`REM_AUTO = `, "the remediation ordinals"},
		// The enums cross the wire as names now, so subtracting two of them
		// is not a sort — it is NaN, and Array.sort leaves the order it found.
		// Silent, and it would put Low findings above High ones.
		{`a.severity - b.severity`, "an arithmetic severity sort"},
		{`a.source - b.source`, "an arithmetic domain sort"},
	} {
		if strings.Contains(js, tc.shape) {
			t.Errorf("app.js has %s again (%s); it must read window.HOSTVEIL_MODEL", tc.what, tc.shape)
		}
	}
}

// severityArrayLiteral renders the severities as the JavaScript array
// literal a hand-written copy of the table would most likely be — the levels
// in the model's own order, which is the order anyone re-adding the table
// would type them in.
func severityArrayLiteral(of func(model.Severity) string) string {
	parts := make([]string, 0, len(model.AllSeverities()))
	for _, s := range model.AllSeverities() {
		parts = append(parts, fmt.Sprintf("%q", of(s)))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
