package main

import (
	"regexp"
	"slices"
	"strconv"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

// The docs restate things the code decides — axis weights, which findings
// have a fix button — and nothing has ever checked that the restatement is
// still true. It was not: the checks table labelled thirteen findings
// "Review" that had no registered fix and were shown as Manual, and the
// scoring section described an additive penalty model two releases after
// it stopped being additive. Both went unnoticed because prose cannot fail
// a build. These tests give it a way to.

var (
	// <tr><td><code>compose.ds016</code></td>…<td>Manual</td></tr>
	findingRow = regexp.MustCompile(`<tr><td><code>([a-z0-9.\-]+)</code></td>.*?<td>([^<]*)</td></tr>`)
	// <tr><td>Container exposure</td><td>20</td></tr> — a whole-cell number,
	// so the severity-share table ("1/2 of what remains") cannot match.
	weightRow = regexp.MustCompile(`<tr><td>([^<]+)</td><td>(\d+)</td></tr>`)
)

// docLangs are the content trees that must agree with the code and with
// each other.
var docLangs = []string{"en", "ko"}

func checksPage(t *testing.T, lang string) string {
	t.Helper()
	b, err := assets.ReadFile("content/" + lang + "/docs/checks.html")
	if err != nil {
		t.Fatalf("read %s checks page: %v", lang, err)
	}
	return string(b)
}

// fixableInDocs maps each language's "Fix" column values to whether they
// promise the user a fix to apply.
var fixableInDocs = map[string]bool{
	"Auto-fix": true, "Review": true, "Manual": false, "Unavailable": false,
	"자동 수정": true, "검토": true, "수동": false, "사용 불가": false,
}

// TestDocumentedFixKindsMatchTheRegistry is the guard for the failure that
// actually shipped: a table promising a fix button for findings the
// registry declines, which Engine.classify demotes to Manual. The column
// was transcribing what each checker asks for, which is only half of how
// remediation is settled.
func TestDocumentedFixKindsMatchTheRegistry(t *testing.T) {
	registry := fix.Default()
	for _, lang := range docLangs {
		rows := findingRow.FindAllStringSubmatch(checksPage(t, lang), -1)
		if len(rows) == 0 {
			t.Fatalf("%s: no finding rows parsed; the table markup changed", lang)
		}
		for _, row := range rows {
			id, kind := row[1], row[2]
			promised, known := fixableInDocs[kind]
			if !known {
				t.Errorf("%s: finding %s has unrecognised fix column %q", lang, id, kind)
				continue
			}
			if registered := registry.Has(id); promised != registered {
				t.Errorf("%s: docs list %s as %q but a fix is registered=%v — a UI would %s",
					lang, id, kind, registered,
					map[bool]string{true: "show no button where the docs promise one", false: "show a button the docs deny"}[promised])
			}
		}
	}
}

// The two languages drift apart one edit at a time; each is a separate file
// and nothing links them.
func TestBothLanguagesDocumentTheSameFindings(t *testing.T) {
	ids := map[string][]string{}
	for _, lang := range docLangs {
		for _, row := range findingRow.FindAllStringSubmatch(checksPage(t, lang), -1) {
			ids[lang] = append(ids[lang], row[1])
		}
		slices.Sort(ids[lang])
	}
	if !slices.Equal(ids["en"], ids["ko"]) {
		t.Errorf("languages document different findings:\n en: %v\n ko: %v", ids["en"], ids["ko"])
	}
}

// TestDocumentedAxisWeightsMatchTheCode pins the weight table against
// axisDefs. The caps are reachable without exporting anything: a scored
// empty report carries each axis's MaxPenalty.
func TestDocumentedAxisWeightsMatchTheCode(t *testing.T) {
	var caps []int
	for _, ax := range model.ScoreReport(nil, nil).Axes {
		caps = append(caps, ax.MaxPenalty)
	}
	slices.Sort(caps)

	for _, lang := range docLangs {
		var documented []int
		for _, row := range weightRow.FindAllStringSubmatch(checksPage(t, lang), -1) {
			n, err := strconv.Atoi(row[2])
			if err != nil {
				continue
			}
			documented = append(documented, n)
		}
		slices.Sort(documented)
		if !slices.Equal(documented, caps) {
			t.Errorf("%s: documented axis weights %v, code has %v", lang, documented, caps)
		}
	}
}

// TestScoringProseTripwire cannot read prose, so it watches the constants
// the prose describes. Changing one without touching the docs leaves four
// pages quietly lying about how the score works; this makes that a build
// failure with a pointer to what to edit.
func TestScoringProseTripwire(t *testing.T) {
	// "One Critical takes half of whatever an axis has left."
	if got := model.SeverityCritical.Penalty() * 2; got != 16 {
		t.Errorf("a Critical no longer costs half an axis (anchor=%d); docs in "+
			"content/{en,ko}/docs/{checks,faq}.html say \"half\" and need rewriting", got)
	}
	// "Counts a quarter as much" / "1/4만 반영됩니다".
	for _, lang := range docLangs {
		page := checksPage(t, lang)
		want := map[string]string{"en": "a quarter as much", "ko": "1/4만 반영"}[lang]
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(page) {
			t.Errorf("%s: checks page no longer states the Unavailable relief (%q); "+
				"if the constant changed, update the prose too", lang, want)
		}
	}
}
