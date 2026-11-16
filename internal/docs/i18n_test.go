package docs

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/fix/fixtest"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/report"
)

// The dashboard's translations live in one catalog per language under
// internal/ui/web/assets/i18n/. app.js reads it in two ways (see "language"
// at the top of app.js): t() looks up text app.js writes, and tr() looks up
// text the server sent, where a {name} in a key stands for any run of text.
// These tests hold the catalog to everything that can reach the page, so a
// new string or finding fails here and never shows up in English by
// surprise.

var dashboardLangs = []string{"ko"}

type catalog struct {
	Messages map[string]string `json:"messages"`
	Server   map[string]string `json:"server"`
	Findings map[string]struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		HowToFix    string `json:"how_to_fix"`
	} `json:"findings"`
}

func loadCatalog(t *testing.T, lang string) catalog {
	t.Helper()
	var c catalog
	raw := readRepoFile(t, filepath.Join("internal", "ui", "web", "assets", "i18n", lang+".json"))
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("%s.json: %v", lang, err)
	}
	return c
}

var placeholder = regexp.MustCompile(`\{(\w+)\}`)

func placeholders(s string) []string {
	var out []string
	for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// keyPattern is app.js's patternFor in Go.
func keyPattern(key string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?s)^")
	last := 0
	for _, m := range placeholder.FindAllStringSubmatchIndex(key, -1) {
		b.WriteString(regexp.QuoteMeta(key[last:m[0]]))
		b.WriteString("(?P<" + key[m[2]:m[3]] + ">.+?)")
		last = m[1]
	}
	b.WriteString(regexp.QuoteMeta(key[last:]))
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// translates is app.js's tr in Go: an exact key in server, or a server key
// whose placeholders match.
func (c catalog) translates(s string) bool {
	if c.Server[s] != "" {
		return true
	}
	for k, v := range c.Server {
		if v != "" && strings.Contains(k, "{") && keyPattern(k).MatchString(s) {
			return true
		}
	}
	return false
}

// appKeys is every literal t("…") in app.js and every data-i18n text and
// data-i18n-aria label in index.html.
func appKeys(t *testing.T) []string {
	t.Helper()
	js := readRepoFile(t, filepath.Join("internal", "ui", "web", "assets", "app.js"))
	var keys []string
	for _, m := range regexp.MustCompile(`\bt\(("(?:[^"\\]|\\.)*")`).FindAllStringSubmatch(js, -1) {
		k, err := strconv.Unquote(m[1])
		if err != nil {
			t.Fatalf("app.js: cannot read t(%s): %v", m[1], err)
		}
		keys = append(keys, k)
	}
	html := readRepoFile(t, filepath.Join("internal", "ui", "web", "assets", "index.html"))
	for _, m := range regexp.MustCompile(`data-i18n>([^<]+)<`).FindAllStringSubmatch(html, -1) {
		keys = append(keys, strings.TrimSpace(m[1]))
	}
	for _, m := range regexp.MustCompile(`aria-label="([^"]+)" data-i18n-aria`).FindAllStringSubmatch(html, -1) {
		keys = append(keys, m[1])
	}
	if len(keys) < 100 {
		t.Fatalf("only %d keys found in app.js and index.html; the pattern is broken", len(keys))
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

func TestEveryDashboardStringIsTranslated(t *testing.T) {
	for _, lang := range dashboardLangs {
		c := loadCatalog(t, lang)
		for _, k := range appKeys(t) {
			v, ok := c.Messages[k]
			if !ok || v == "" {
				t.Errorf("%s: no translation for %q", lang, k)
				continue
			}
			if !slices.Equal(placeholders(k), placeholders(v)) {
				t.Errorf("%s: %q has placeholders %v, its translation %v", lang, k, placeholders(k), placeholders(v))
			}
		}
	}
}

// The labels app.js reads out of /model.js, the export list and the
// engine's re-check notes go through tr(), so every one needs a row.
func TestEveryModelLabelIsTranslated(t *testing.T) {
	var labels []string
	for _, s := range model.AllSources() {
		labels = append(labels, s.Label())
	}
	for _, r := range []model.RemediationKind{model.RemediationUnset, model.RemediationAuto,
		model.RemediationReview, model.RemediationManual, model.RemediationUnavailable} {
		labels = append(labels, r.Label())
	}
	for _, s := range model.AllSeverities() {
		n := s.String()
		labels = append(labels, n, strings.ToUpper(n[:1])+n[1:])
	}
	for _, b := range model.Bands() {
		labels = append(labels, b.Verdict())
	}
	for _, f := range report.All() {
		labels = append(labels, f.Label)
	}
	for _, v := range []model.FixVerification{model.VerifyNotRun, model.VerifyGone, model.VerifyPending,
		model.VerifyStillPresent, model.VerifyUnavailable} {
		for _, hint := range []string{"", "app"} {
			if n := v.Note(hint); n != "" {
				labels = append(labels, n)
			}
		}
	}
	for _, lang := range dashboardLangs {
		c := loadCatalog(t, lang)
		for _, l := range labels {
			if !c.translates(l) {
				t.Errorf("%s: no translation for the label %q", lang, l)
			}
		}
	}
}

func TestEveryFindingIsTranslated(t *testing.T) {
	ids := emittedFindingIDs(t)
	for _, lang := range dashboardLangs {
		c := loadCatalog(t, lang)
		for _, id := range ids {
			e, ok := c.Findings[id]
			switch {
			case !ok:
				t.Errorf("%s: finding %s has no entry", lang, id)
			case e.Title == "" || e.Description == "" || e.HowToFix == "":
				t.Errorf("%s: finding %s needs a title, a description and how_to_fix", lang, id)
			}
		}
		for id := range c.Findings {
			if !slices.Contains(ids, id) {
				t.Errorf("%s: finding %s is translated and no checker reports it", lang, id)
			}
		}
	}
}

// Every sentence the fix registry builds reaches the preview: the fix's
// label, each alternative's label, benefit, warning, what to check first,
// and when it takes effect. So does the reason a finding has no fix.
func TestEveryFixStringIsTranslated(t *testing.T) {
	r := fix.Default()
	var texts []string
	for _, id := range emittedFindingIDs(t) {
		fx, ok, err := r.Build(fixtest.Finding(id))
		if err != nil || !ok {
			if why := fix.WhyNoFix(id); why != "" {
				texts = append(texts, why)
			}
			continue
		}
		texts = append(texts, fx.Label)
		for _, a := range fx.Actions {
			texts = append(texts, a.Label, a.Benefit, a.Warning, a.CheckFirst, a.TakesEffectOn)
		}
	}
	for _, lang := range dashboardLangs {
		c := loadCatalog(t, lang)
		for _, s := range texts {
			if s != "" && !c.translates(s) {
				t.Errorf("%s: no translation for %q", lang, s)
			}
		}
	}
}

// A translation takes only the placeholders its key captured, and a key
// that cannot compile would break every tr() call in the page.
func TestCatalogPlaceholdersMatch(t *testing.T) {
	for _, lang := range dashboardLangs {
		c := loadCatalog(t, lang)
		for _, table := range []map[string]string{c.Messages, c.Server} {
			for k, v := range table {
				kp := placeholders(k)
				for _, p := range placeholders(v) {
					if !slices.Contains(kp, p) {
						t.Errorf("%s: %q uses {%s}, which its key does not capture", lang, v, p)
					}
				}
				if len(placeholder.FindAllString(k, -1)) != len(kp) {
					t.Errorf("%s: key %q repeats a placeholder name", lang, k)
				}
			}
		}
		// A server key is a pattern over any text the server sends, so one
		// with almost no literal text in it would rewrite sentences it was
		// never written for.
		for k := range c.Server {
			if strings.Contains(k, "{") && len(placeholder.ReplaceAllString(k, "")) < 6 {
				t.Errorf("%s: server key %q has too little literal text to match safely", lang, k)
			}
		}
	}
}
