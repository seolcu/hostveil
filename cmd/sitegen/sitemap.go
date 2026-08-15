package main

import (
	"fmt"
	"image"
	_ "image/png"
	"os"
	"path/filepath"
	"strings"
)

// The site had 32 pages, no sitemap and no robots.txt — so the only route in
// for a crawler was whatever it happened to follow from the landing page, and
// the Korean half is reachable only through a language switcher.
//
// Both files are generated here rather than committed by hand, and the URLs
// come from the render loops rather than from a second list. main() already
// computes View.Canonical for every page it writes; a page that is rendered is
// therefore in the sitemap by construction, and a page that is not rendered
// cannot be. That is the same move cmd/sitegen/changelog.go makes for the
// changelog: derive, never copy.

// page is one rendered URL and its two language alternates, captured as the
// page is written.
type page struct {
	canonical, en, ko string
}

// sitemap renders the URL set as a sitemap with hreflang alternates.
//
// Deliberately no <lastmod>, <changefreq> or <priority>. A real lastmod needs
// a file mtime or a build timestamp, and either would make the output differ
// between two runs of the same commit — which CI checks with
// `git diff --exit-code site/`, and which the whole design of this generator
// rests on. A fake one is worse than none. The other two elements have been
// ignored by every major crawler for years.
//
// The xhtml:link alternates mirror what head.tmpl already emits per page, so a
// crawler is told the same thing twice by two mechanisms that cannot disagree:
// both are built from the same View.
func sitemap(pages []page) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"` + "\n")
	b.WriteString(`        xmlns:xhtml="http://www.w3.org/1999/xhtml">` + "\n")
	for _, p := range pages {
		b.WriteString("  <url>\n")
		fmt.Fprintf(&b, "    <loc>%s</loc>\n", escText(p.canonical))
		fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"en\" href=\"%s\"/>\n", escAttr(p.en))
		fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"ko\" href=\"%s\"/>\n", escAttr(p.ko))
		fmt.Fprintf(&b, "    <xhtml:link rel=\"alternate\" hreflang=\"x-default\" href=\"%s\"/>\n", escAttr(p.en))
		b.WriteString("  </url>\n")
	}
	b.WriteString("</urlset>\n")
	return b.String()
}

// robots allows everything and points at the sitemap.
//
// Nothing is disallowed on purpose. The one non-page file the site serves is
// install.sh, which .github/workflows/pages.yml copies in at deploy time and
// which the landing page tells people to curl — a site that told crawlers to
// ignore its own install command would be hiding the thing it advertises.
func robots() string {
	return "User-agent: *\nAllow: /\n\nSitemap: " + siteURL + "/sitemap.xml\n"
}

func writeSitemap(outDir string, pages []page) error {
	//nolint:gosec // G306: generated site output, meant to be readable — see render
	if err := os.WriteFile(filepath.Join(outDir, "sitemap.xml"), []byte(sitemap(pages)), 0o644); err != nil {
		return err
	}
	//nolint:gosec // G306: generated site output, meant to be readable — see render
	return os.WriteFile(filepath.Join(outDir, "robots.txt"), []byte(robots()), 0o644)
}

// ogImageSize reads the dimensions of the card image out of the file itself.
//
// og:image:width and og:image:height are two integers describing a third
// thing, which is the shape this repository keeps getting wrong — the
// measurements page, the READMEs, a screenshot naming findings that do not
// exist. Decoding the PNG header costs nothing and removes the possibility:
// re-shoot the dashboard at another size and the tags follow it.
//
// A failure here is not fatal. The tags are a hint to a link unfurler, and a
// site that refuses to build because it could not measure a PNG would be
// trading a real thing for a cosmetic one; the tags are simply omitted.
func ogImageSize() (int, int) {
	f, err := os.Open(filepath.Join("site", "assets", "web.png"))
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}
