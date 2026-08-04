package web

import (
	"bytes"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/ui/theme"
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

// Both paint attributes, not just fill. The mark is linework — a package
// outline, twelve pins — so its most prominent colour is a stroke, and a
// fill-only extraction would have walked straight past it. `fill="none"` is
// not a colour and does not match, which is what keeps the outlined package
// from failing the role check.
var svgPaint = regexp.MustCompile(`(?:fill|stroke)="(#[0-9a-fA-F]{6})"`)

// internal/ui/theme is the only place a color is written down; the two brand
// SVGs are the one static exception, because a favicon is fetched before any
// theme is known. That exception is tolerable only while their hexes stay
// the default theme's roles — the Ink2 tile, the Bone package and pins, and
// the Safe core. If the palette moves, this fails instead of the mark
// quietly drifting off-brand, which is exactly what it did when Instrument
// was retired: the mark kept its bone-and-teal until this test said otherwise.
//
// It reads Default() rather than a named theme on purpose. The mark belongs
// to whatever hostveil opens in, and pinning it to an ID would survive that
// ID being replaced.
func TestBrandMarkColorsAreTheDefaultPalette(t *testing.T) {
	p := theme.Default().Palette
	role := map[string]string{p.Ink2: "Ink2", p.Bone: "Bone", p.Safe: "Safe"}

	for _, name := range []string{"assets/favicon.svg", "assets/mark.svg"} {
		b, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		paints := svgPaint.FindAllStringSubmatch(string(b), -1)
		if len(paints) == 0 {
			t.Fatalf("%s declares no paints — the extraction is broken, not the mark", name)
		}
		seen := map[string]bool{}
		for _, m := range paints {
			hex := strings.ToLower(m[1])
			r, ok := role[hex]
			if !ok {
				t.Errorf("%s paints with %s, which is no Ink2/Bone/Safe of the default theme", name, hex)
				continue
			}
			seen[r] = true
		}
		// Both variants are the same figure: a bone package around a safe
		// core. Losing either color is losing half the mark's meaning.
		for _, want := range []string{"Bone", "Safe"} {
			if !seen[want] {
				t.Errorf("%s no longer uses the %s role", name, want)
			}
		}
	}
}

// The marketing site cannot serve the dashboard's embedded assets, so it
// keeps its own copies — and copies are how hostveil ended up with four
// hand-drawn marks in the first place: a favicon, a status-bar mark, a
// bordered box built in site/styles.css, and a fourth figure inlined as a
// data URI in the page head, none of which had ever been seen side by side.
//
// Byte equality rather than "looks similar": the whole point of picking one
// mark is that there is one drawing, and a copy that has been nudged is a
// second drawing with a shared name.
func TestSiteBrandAssetsMatchTheDashboard(t *testing.T) {
	for _, name := range []string{"favicon.svg", "mark.svg"} {
		want, err := assets.ReadFile("assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join("..", "..", "..", "site", "assets", name))
		if err != nil {
			t.Fatalf("the site has no copy of %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("site/assets/%s has drifted from the dashboard's copy; "+
				"copy it across rather than editing one of them", name)
		}
	}
}
