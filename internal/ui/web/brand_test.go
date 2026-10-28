package web

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// The brand mark ships as two files on purpose: favicon.svg keeps an opaque
// tile because a browser tab has no known background, and mark.svg drops it
// so the status-bar figure dissolves into whatever palette the page runs in.
// index.html asks for one and app.css paints the other, so a missing or
// misnamed asset is a broken tab icon or an empty 20px gap before the brand
// text — neither of which any Go test noticed when the files landed.
func TestBrandAssetsAreServed(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	for _, path := range []string{"/favicon.svg", "/mark.svg"} {
		resp, err := authedClient(t, s, srv).Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s returned %d", path, resp.StatusCode)
		}
		// The browser refuses to rasterize an SVG served under another type,
		// so the icon silently disappears rather than erroring.
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
			t.Errorf("%s Content-Type = %q, want image/svg+xml", path, ct)
		}
		if !strings.Contains(string(body), "<svg") {
			t.Errorf("%s does not look like an SVG:\n%s", path, body)
		}
	}
}

// The page has to actually reference both variants, each in its own place:
// the tab icon from index.html, the status-bar mark from app.css. Renaming
// an asset without updating its reference degrades silently — the dashboard
// still loads, just without its mark.
func TestBrandAssetsAreReferenced(t *testing.T) {
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), `rel="icon"`) || !strings.Contains(string(index), `href="/favicon.svg"`) {
		t.Error(`index.html does not link the favicon (rel="icon" href="/favicon.svg")`)
	}

	css, err := assets.ReadFile("assets/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), "url(/mark.svg)") {
		t.Error("app.css no longer paints the brand from /mark.svg")
	}
	// The mark replaced a ▚ glyph that rendered as tofu in fonts without the
	// quadrant block; the character must not creep back into either file.
	for name, b := range map[string][]byte{"index.html": index, "app.css": css} {
		if strings.Contains(string(b), "▚") {
			t.Errorf("%s still contains the ▚ placeholder glyph the mark replaced", name)
		}
	}
}
