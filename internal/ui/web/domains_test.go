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
	js := domainsJS()
	for _, src := range model.AllSources() {
		// The whole entry, not its pieces. A domain present but nameless is
		// the failure mode that shipped: app.js falls back to String(s) and
		// draws the integer, which reads as a rendering glitch rather than
		// as a missing table entry.
		want := fmt.Sprintf("  %d: {id: %q, label: %q},", int(src), src.String(), src.Label())
		if src.Label() == "" {
			t.Errorf("%q (%d) reaches the dashboard with no label", src.String(), int(src))
			continue
		}
		if !strings.Contains(js, want) {
			t.Errorf("/domains.js is missing %s", strings.TrimSpace(want))
		}
	}
	// Nothing-extracted guard: an empty generator would satisfy nothing
	// above if AllSources were also empty, and would pass silently.
	if n := strings.Count(js, "label:"); n != len(model.AllSources()) {
		t.Fatalf("/domains.js declares %d labels for %d domains", n, len(model.AllSources()))
	}
}

// The table is only useful if the page can actually fetch it. It is a
// blocking script in <head>, so a 404 here is a dashboard that renders its
// domain chips as integers — the original bug, reintroduced through the
// routing table instead of the data.
func TestDomainsScriptIsServedAndReferenced(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := authedClient(t, s, srv).Get(srv.URL + "/domains.js")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/domains.js returned %d", resp.StatusCode)
	}
	// A script served as anything else is refused by the browser, and the
	// page then runs app.js against an undefined table.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("/domains.js Content-Type = %q, want text/javascript", ct)
	}
	if !strings.Contains(string(body), "window.HOSTVEIL_DOMAINS") {
		t.Errorf("/domains.js does not define window.HOSTVEIL_DOMAINS:\n%s", body)
	}

	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), `src="/domains.js"`) {
		t.Error("index.html does not load /domains.js")
	}

	// And the copy it replaced must not come back. An object literal
	// mapping integers to names in app.js is exactly the shape that drifted.
	app, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(app), `1: "Container"`) {
		t.Error("app.js has a hand-written domain table again; it must read window.HOSTVEIL_DOMAINS")
	}
}
