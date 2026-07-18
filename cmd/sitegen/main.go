// Command sitegen renders the hostveil website (site/) from shared templates,
// per-page content fragments, and one metadata manifest (pages.json).
//
// It is the single source of truth for the site's chrome (head, nav, sidebar,
// footer) and the en/ko split. Regenerate and commit the output:
//
//	go run ./cmd/sitegen         # writes into ./site
//	go run ./cmd/sitegen out     # writes into ./out
//
// The output is meant to stay byte-identical unless a template, fragment, or
// manifest entry changes — CI can enforce that with `git diff --exit-code site`.
package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

const siteURL = "https://hostveil.seolcu.com"

//go:embed templates/*.tmpl
//go:embed pages.json
//go:embed all:content
var assets embed.FS

// Meta is one page's per-language head metadata (from pages.json).
type Meta struct {
	Title         string `json:"title"`
	Description   string `json:"description"`
	OGTitle       string `json:"ogTitle"`
	OGDescription string `json:"ogDescription"`
	OGType        string `json:"ogType,omitempty"`
	Nav           string `json:"nav,omitempty"`
}

type DocPage struct {
	Slug   string `json:"slug"`
	Group  string `json:"group"`
	OGType string `json:"ogType"`
	En     Meta   `json:"en"`
	Ko     Meta   `json:"ko"`
}

type Manifest struct {
	Landing map[string]Meta `json:"landing"`
	Docs    []DocPage       `json:"docs"`
}

// Strings holds every piece of localized site chrome.
type Strings struct {
	SkipLink, NavAria, BrandAria                                     string
	NavDocs, NavFeatures, NavInstall                                 string
	LNavFeatures, LNavChecks, LNavScreenshots, LNavInstall, LNavDocs string
	SidebarAria, SidebarToggle                                       string
	SearchPlaceholder, SearchAria, SearchResultsAria                 string
	GroupGettingStarted, GroupGuide, GroupReference                  string
	FooterTagline, FooterNavAria, FooterDocs, FooterReleases         string
	LightboxAria                                                     string
}

var strings_ = map[string]Strings{
	"en": {
		SkipLink: "Skip to content", NavAria: "Primary navigation", BrandAria: "hostveil home",
		NavDocs: "Docs", NavFeatures: "Features", NavInstall: "Install",
		LNavFeatures: "Features", LNavChecks: "Checks", LNavScreenshots: "Screenshots", LNavInstall: "Install", LNavDocs: "Docs",
		SidebarAria: "Documentation navigation", SidebarToggle: "Documentation menu",
		SearchPlaceholder: "Search the docs…", SearchAria: "Search documentation", SearchResultsAria: "Search results",
		GroupGettingStarted: "Getting started", GroupGuide: "Guide", GroupReference: "Reference",
		FooterTagline: "Guided security hardening for self-hosted Linux servers.", FooterNavAria: "Footer links",
		FooterDocs: "Docs", FooterReleases: "Releases",
		LightboxAria: "Enlarged screenshot",
	},
	"ko": {
		SkipLink: "본문으로 건너뛰기", NavAria: "주요 내비게이션", BrandAria: "hostveil 홈",
		NavDocs: "문서", NavFeatures: "기능", NavInstall: "설치",
		LNavFeatures: "기능", LNavChecks: "점검", LNavScreenshots: "스크린샷", LNavInstall: "설치", LNavDocs: "문서",
		SidebarAria: "문서 내비게이션", SidebarToggle: "문서 메뉴",
		SearchPlaceholder: "문서 검색…", SearchAria: "문서 검색", SearchResultsAria: "검색 결과",
		GroupGettingStarted: "시작하기", GroupGuide: "가이드", GroupReference: "레퍼런스",
		FooterTagline: "셀프호스팅 리눅스 서버를 위한 가이드형 보안 강화.", FooterNavAria: "푸터 링크",
		FooterDocs: "문서", FooterReleases: "릴리스",
		LightboxAria: "확대된 스크린샷",
	},
}

var langName = map[string]string{"en": "English", "ko": "한국어"}

// Item is one sidebar link; Group is one labelled sidebar section.
type Item struct{ Href, Label, ActiveAttr string }
type Group struct {
	Heading string
	Items   []Item
}

// View is the fully-resolved model handed to a template.
type View struct {
	Strings
	Lang                                               string
	Title, Description, OGTitle, OGDescription, OGType string
	Canonical, HrefEn, HrefKo                          string
	OGLocaleLine, AssetLinks                           string
	DocsCurrentAttr                                    string
	LDocsHref                                          string
	LangHref, LangLang, LangLabel                      string
	Groups                                             []Group
	Content                                            string
}

func other(lang string) string {
	if lang == "en" {
		return "ko"
	}
	return "en"
}

// docsPath is the site-absolute path of a docs page in the given language.
func docsPath(lang, slug string) string {
	base := "/docs/"
	if lang == "ko" {
		base = "/ko/docs/"
	}
	if slug == "index" {
		return base
	}
	return base + slug
}

func landingPath(lang string) string {
	if lang == "ko" {
		return "/ko/"
	}
	return "/"
}

// assetLinks builds the <link>/<script> block for a page type and language,
// matching the exact ordering and per-language depth of the original site.
func assetLinks(kind, lang string) string {
	prefix := map[[2]string]string{
		{"landing", "en"}: "", {"landing", "ko"}: "../",
		{"docs", "en"}: "../", {"docs", "ko"}: "../../",
	}[[2]string{kind, lang}]
	var b strings.Builder
	link := func(href string) { fmt.Fprintf(&b, "    <link rel=\"stylesheet\" href=\"%s\">\n", href) }
	script := func(src string) { fmt.Fprintf(&b, "    <script src=\"%s\" defer></script>\n", src) }
	link(prefix + "styles.css")
	if kind == "docs" {
		link(prefix + "docs.css")
		script(prefix + "docs.js")
	} else {
		script(prefix + "script.js")
	}
	if lang == "en" { // lang-suggest banner is English-only
		script(prefix + "lang-suggest.js")
	}
	return b.String()
}

func ogLocaleLine(lang string) string {
	if lang == "ko" {
		return "    <meta property=\"og:locale\" content=\"ko_KR\">\n"
	}
	return ""
}

func groupHeading(s Strings, key string) string {
	switch key {
	case "getting-started":
		return s.GroupGettingStarted
	case "guide":
		return s.GroupGuide
	default:
		return s.GroupReference
	}
}

// sidebar builds the three grouped sections, marking the current slug active.
func sidebar(m Manifest, lang, current string) []Group {
	s := strings_[lang]
	order := []string{"getting-started", "guide", "reference"}
	groups := make([]Group, 0, len(order))
	for _, key := range order {
		g := Group{Heading: groupHeading(s, key)}
		for _, d := range m.Docs {
			if d.Group != key {
				continue
			}
			href := d.Slug
			if d.Slug == "index" {
				href = "./"
			}
			label := d.En.Nav
			if lang == "ko" {
				label = d.Ko.Nav
			}
			active := ""
			if d.Slug == current {
				active = ` class="active"`
			}
			g.Items = append(g.Items, Item{Href: href, Label: label, ActiveAttr: active})
		}
		groups = append(groups, g)
	}
	return groups
}

func base(lang string, meta Meta, ogType string) View {
	oth := other(lang)
	return View{
		Strings:       strings_[lang],
		Lang:          lang,
		Title:         meta.Title,
		Description:   meta.Description,
		OGTitle:       meta.OGTitle,
		OGDescription: meta.OGDescription,
		OGType:        ogType,
		OGLocaleLine:  ogLocaleLine(lang),
		LangLang:      oth,
		LangLabel:     langName[oth],
	}
}

func render(t *template.Template, name, out string, v View) error {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, v); err != nil {
		return err
	}
	body := strings.TrimRight(buf.String(), "\n") + "\n"
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, []byte(body), 0o644)
}

func fragment(kind, lang, slug string) (string, error) {
	var p string
	if kind == "landing" {
		p = filepath.Join("content", lang, "index.html")
	} else {
		p = filepath.Join("content", lang, "docs", slug+".html")
	}
	b, err := assets.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n"), nil
}

func main() {
	outDir := "site"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	raw, err := assets.ReadFile("pages.json")
	must(err)
	var m Manifest
	must(json.Unmarshal(raw, &m))

	t := template.Must(template.ParseFS(assets, "templates/*.tmpl"))

	count := 0
	for _, lang := range []string{"en", "ko"} {
		// landing
		v := base(lang, m.Landing[lang], m.Landing[lang].OGType)
		v.Canonical = siteURL + landingPath(lang)
		v.HrefEn, v.HrefKo = siteURL+"/", siteURL+"/ko/"
		v.LangHref = landingPath(other(lang))
		v.LDocsHref = docsPath(lang, "index")
		v.AssetLinks = assetLinks("landing", lang)
		frag, err := fragment("landing", lang, "")
		must(err)
		v.Content = frag
		out := filepath.Join(outDir, "index.html")
		if lang == "ko" {
			out = filepath.Join(outDir, "ko", "index.html")
		}
		must(render(t, "page", out, v))
		count++

		// docs
		for _, d := range m.Docs {
			meta := d.En
			if lang == "ko" {
				meta = d.Ko
			}
			v := base(lang, meta, d.OGType)
			v.Canonical = siteURL + docsPath(lang, d.Slug)
			v.HrefEn = siteURL + docsPath("en", d.Slug)
			v.HrefKo = siteURL + docsPath("ko", d.Slug)
			v.LangHref = docsPath(other(lang), d.Slug)
			v.AssetLinks = assetLinks("docs", lang)
			v.Groups = sidebar(m, lang, d.Slug)
			if d.Slug == "index" {
				v.DocsCurrentAttr = ` aria-current="page"`
			}
			frag, err := fragment("docs", lang, d.Slug)
			must(err)
			v.Content = frag
			var out string
			if lang == "ko" {
				out = filepath.Join(outDir, "ko", "docs", d.Slug+".html")
			} else {
				out = filepath.Join(outDir, "docs", d.Slug+".html")
			}
			must(render(t, "docs", out, v))
			count++
		}
	}
	fmt.Printf("sitegen: wrote %d pages into %s/\n", count, outDir)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "sitegen:", err)
		os.Exit(1)
	}
}
