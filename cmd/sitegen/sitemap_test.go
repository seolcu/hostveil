package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestTheSitemapListsEveryRenderedPageExactlyOnce.
//
// The sitemap is built from the URLs the render loops compute, which is what
// makes "a page that is rendered is in the sitemap" true by construction. This
// checks the construction actually holds: it counts the HTML files sitegen
// wrote and requires one <loc> each, no more and no fewer.
//
// A sitemap that quietly lost a page would be indistinguishable from a
// complete one — which is the failure mode of every reference in this
// repository, and the reason the generator derives rather than copies.
func TestTheSitemapListsEveryRenderedPageExactlyOnce(t *testing.T) {
	root := repoRootFromSitegen(t)
	raw, err := os.ReadFile(filepath.Join(root, "site", "sitemap.xml"))
	if err != nil {
		t.Fatalf("no sitemap in the committed site: %v", err)
	}

	var doc struct {
		URLs []struct {
			Loc   string `xml:"loc"`
			Links []struct {
				Hreflang string `xml:"hreflang,attr"`
				Href     string `xml:"href,attr"`
			} `xml:"link"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the sitemap is not well-formed XML, so no crawler will read it: %v", err)
	}

	var rendered int
	for _, g := range []string{"*.html", "ko/*.html", "docs/*.html", "ko/docs/*.html"} {
		m, gerr := filepath.Glob(filepath.Join(root, "site", g))
		if gerr != nil {
			t.Fatal(gerr)
		}
		rendered += len(m)
	}
	if rendered == 0 {
		t.Fatal("found no rendered pages, so this test would pass on an empty sitemap")
	}
	if len(doc.URLs) != rendered {
		t.Errorf("the site has %d pages and the sitemap lists %d", rendered, len(doc.URLs))
	}

	seen := map[string]bool{}
	for _, u := range doc.URLs {
		if seen[u.Loc] {
			t.Errorf("%s is listed twice", u.Loc)
		}
		seen[u.Loc] = true
		if !strings.HasPrefix(u.Loc, siteURL+"/") {
			t.Errorf("%q is not an absolute URL under %s; a relative loc is ignored", u.Loc, siteURL)
		}
		// Every page exists in both languages, so every entry carries all
		// three alternates — the same triple head.tmpl emits.
		langs := map[string]bool{}
		for _, l := range u.Links {
			langs[l.Hreflang] = true
		}
		for _, want := range []string{"en", "ko", "x-default"} {
			if !langs[want] {
				t.Errorf("%s has no %s alternate; the Korean half of this site is reachable "+
					"only through a language switcher, which is exactly what these are for", u.Loc, want)
			}
		}
	}
}

// TestTheSitemapCarriesNoTimestamp.
//
// <lastmod> is the obvious thing to add and the one thing that cannot be
// added. Its honest sources are a file mtime or a build time, and either makes
// two runs of the same commit produce different bytes — which CI checks with
// `git diff --exit-code site/`, and which the whole generator rests on. A
// constant date would be a lie a crawler acts on.
//
// Written down as a test rather than a comment because the next person to read
// the sitemap spec will reach for it.
func TestTheSitemapCarriesNoTimestamp(t *testing.T) {
	raw := string(readSite(t, "sitemap.xml"))
	for _, tag := range []string{"<lastmod>", "<changefreq>", "<priority>"} {
		if strings.Contains(raw, tag) {
			t.Errorf("the sitemap carries %s. lastmod is either non-deterministic or false, "+
				"and the other two are ignored by every major crawler — see sitemap().", tag)
		}
	}
}

func TestRobotsPointsAtTheSitemap(t *testing.T) {
	raw := string(readSite(t, "robots.txt"))
	if !strings.Contains(raw, "Sitemap: "+siteURL+"/sitemap.xml") {
		t.Errorf("robots.txt does not name the sitemap, which is the only way most crawlers "+
			"find one:\n%s", raw)
	}
	if strings.Contains(raw, "Disallow: /") {
		t.Error("robots.txt disallows the whole site")
	}
}

// TestTheCardImageDimensionsMatchTheFile.
//
// og:image:width and og:image:height are two integers describing a third
// thing. They are read out of the PNG at generation time so they cannot
// disagree with it; this checks that the reading worked, because the failure
// mode of ogImageSize is to return 0,0 and emit two tags a scraper will
// believe.
func TestTheCardImageDimensionsMatchTheFile(t *testing.T) {
	root := repoRootFromSitegen(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	w, h := ogImageSize()
	if w == 0 || h == 0 {
		t.Fatal("could not read site/assets/web.png; the card would advertise a 0x0 image")
	}

	page := string(readSite(t, "index.html"))
	for _, want := range []string{
		`<meta property="og:image:width" content="` + strconv.Itoa(w) + `">`,
		`<meta property="og:image:height" content="` + strconv.Itoa(h) + `">`,
		`<meta name="twitter:card" content="summary_large_image">`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the landing page does not carry %s", want)
		}
	}
}

func readSite(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRootFromSitegen(t), "site", name))
	if err != nil {
		t.Fatalf("read site/%s: %v", name, err)
	}
	return b
}
