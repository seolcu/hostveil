package main

import (
	"encoding/json"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/fix/fixtest"
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
	// <span class="sev exposed">EXPOSED</span>, wherever one appears.
	severityChip = regexp.MustCompile(`<span class="sev ([a-z\-]+)">([^<]*)</span>`)
	// The severity cell of a finding row: everything between the description
	// and the Fix column, which is where one or two chips live.
	severityCell = regexp.MustCompile(`<tr><td><code>([a-z0-9.\-]+)</code></td>.*?<td>((?:<span class="sev [^>]*>[^<]*</span>[^<]*)+)</td><td>[^<]*</td></tr>`)
)

// docLangs are the content trees that must agree with the code and with
// each other.
var docLangs = []string{"en", "ko"}

func checksPage(t *testing.T, lang string) string { return docsPage(t, lang, "checks") }

func docsPage(t *testing.T, lang, slug string) string {
	t.Helper()
	b, err := assets.ReadFile("content/" + lang + "/docs/" + slug + ".html")
	if err != nil {
		t.Fatalf("read %s %s page: %v", lang, slug, err)
	}
	return string(b)
}

// kindLabels is each language's user-facing name for every remediation kind
// a finding can carry.
//
// The docs used to be read through a map to a bare fixable/not-fixable bool,
// which made "Auto-fix" and "Review" the same answer — so the column could
// promise unattended application of a fix the registry shapes as Review and
// nothing would say a word. The difference between those two is the whole
// subject of the fixing page: one of them is what `fix --all` runs on its own.
//
// RemediationUnset has no entry because no user can be shown one;
// TestFixingPageDocumentsEveryKindAUserCanSee asserts that rather than
// assuming it.
var kindLabels = map[string]map[model.RemediationKind]string{
	"en": {
		model.RemediationAuto:        "Auto-fix",
		model.RemediationReview:      "Review",
		model.RemediationManual:      "Manual",
		model.RemediationUnavailable: "Unavailable",
	},
	"ko": {
		model.RemediationAuto:        "자동 수정",
		model.RemediationReview:      "검토",
		model.RemediationManual:      "수동",
		model.RemediationUnavailable: "사용 불가",
	},
}

// kindInDocs inverts kindLabels: a Fix-column string to the kind it names,
// in whichever language wrote it.
var kindInDocs = func() map[string]model.RemediationKind {
	out := map[string]model.RemediationKind{}
	for _, byKind := range kindLabels {
		for kind, label := range byKind {
			out[label] = kind
		}
	}
	return out
}()

// checkerAsksForMore records the findings whose documented kind is
// deliberately stricter than the shape of the registered fix, and why.
//
// The kind a user sees is the stricter of two sources (see Engine.classify),
// and only one of them is reachable from here: the registry can be built,
// the checker cannot without a live host. So the invariant this file can
// enforce is one-sided — the column may never be *less* cautious than the
// registry's shape — and every place it is more cautious is the checker
// asking for a human, which belongs in writing.
//
// Every entry is an SSH directive that can end the operator's own session.
// The edit is reversible on disk and rolling it back needs the access it
// just removed, which is criterion 2 of the Auto standard in
// internal/fix/register.go, not criterion 1.
var checkerAsksForMore = map[string]string{
	"ssh.passwordauth":   "disabling passwords locks out anyone whose key is not already working",
	"ssh.gatewayports":   "a published tunnel may be the only route to a service, including the operator's",
	"ssh.hostbasedauth":  "the trusting host may be how the operator gets in",
	"ssh.kbdinteractive": "PAM one-time codes run through the same mechanism, so this can disable 2FA logins",
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
			id, col := row[1], row[2]
			documented, known := kindInDocs[col]
			if !known {
				t.Errorf("%s: finding %s has unrecognised fix column %q", lang, id, col)
				continue
			}
			if documented.IsFixable() != registry.Has(id) {
				t.Errorf("%s: docs list %s as %q but a fix is registered=%v — a UI would %s",
					lang, id, col, registry.Has(id),
					map[bool]string{true: "show no button where the docs promise one", false: "show a button the docs deny"}[documented.IsFixable()])
				continue
			}
			if !registry.Has(id) {
				continue
			}

			// EffectiveKind, not Kind: an Auto-shaped fix that runs a command
			// reaches the user as Review, and the column has to say so. This
			// is the half of the resolution the docs used to bake in from the
			// wrong side — updates.disabled is registered Auto and documented
			// Review, and nothing checked that the two agreed for the reason
			// they do.
			fx, ok, err := registry.Build(fixtest.Finding(id))
			if err != nil || !ok {
				t.Errorf("%s: cannot build %s to check its documented kind: ok=%v err=%v", lang, id, ok, err)
				continue
			}
			switch effective := fx.EffectiveKind(); {
			case documented < effective:
				t.Errorf("%s: docs list %s as %q, but the registered fix resolves to %v — "+
					"the column is less cautious than the fix a user is handed",
					lang, id, col, effective)
			case documented > effective:
				if _, deliberate := checkerAsksForMore[id]; !deliberate {
					t.Errorf("%s: docs list %s as %q while the registry shapes it %v — "+
						"if a checker declares the stricter kind, say so in checkerAsksForMore; "+
						"otherwise the column is wrong", lang, id, col, effective)
				}
			}
		}
	}
}

// A finding listed in checkerAsksForMore that the registry has caught up
// with is a stale exception, and a stale exception is a hole: it silently
// re-permits the mismatch the list exists to make deliberate.
func TestNoStaleCheckerAsksForMoreEntries(t *testing.T) {
	registry := fix.Default()
	for _, lang := range docLangs {
		documented := map[string]model.RemediationKind{}
		for _, row := range findingRow.FindAllStringSubmatch(checksPage(t, lang), -1) {
			if k, ok := kindInDocs[row[2]]; ok {
				documented[row[1]] = k
			}
		}
		for id := range checkerAsksForMore {
			doc, listed := documented[id]
			if !listed {
				t.Errorf("%s: checkerAsksForMore lists %s but the checks table does not", lang, id)
				continue
			}
			fx, ok, err := registry.Build(fixtest.Finding(id))
			if err != nil || !ok {
				t.Errorf("%s: checkerAsksForMore lists %s but it has no buildable fix: ok=%v err=%v", lang, id, ok, err)
				continue
			}
			if doc <= fx.EffectiveKind() {
				t.Errorf("%s: %s is no longer documented stricter than its fix (%v vs %v) — drop the "+
					"checkerAsksForMore entry so the exact check applies again", lang, id, doc, fx.EffectiveKind())
			}
		}
	}
}

// TestFixingPageDocumentsEveryKindAUserCanSee closes the loop the fixing
// page's classification table left open: it lists four kinds and the enum
// has five, with nothing saying which one is missing or why.
//
// The absent one is RemediationUnset, and its absence is correct rather than
// an oversight — Finding.Validate rejects an unset remediation and the engine
// drops those before any UI sees them, so no user can ever be shown one. That
// is a claim about the model, so this asserts it rather than restating it.
func TestFixingPageDocumentsEveryKindAUserCanSee(t *testing.T) {
	if (model.Finding{ID: "x", Title: "t", Source: model.SourceSSH}).Validate() == nil {
		t.Fatal("an unset remediation now survives Finding.Validate, so a user can reach one; " +
			"the fixing page's classification table needs a row for it")
	}
	for _, lang := range docLangs {
		b, err := assets.ReadFile("content/" + lang + "/docs/fixing.html")
		if err != nil {
			t.Fatalf("read %s fixing page: %v", lang, err)
		}
		page := string(b)
		for _, kind := range model.AllRemediationKinds() {
			if kind == model.RemediationUnset {
				continue
			}
			label, named := kindLabels[lang][kind]
			if !named {
				t.Errorf("%s: no label for %v; add one to kindLabels", lang, kind)
				continue
			}
			if !strings.Contains(page, "<strong>"+label+"</strong>") {
				t.Errorf("%s: the fixing page's classification table has no row for %v (%q)", lang, kind, label)
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

// reliefProse is how each language spells the Unavailable relief divisor.
// Keying it by the number is what makes the constant and the sentence one
// edit: changing the divisor lands on a key with no phrase, and the test says
// so instead of passing.
var reliefProse = map[int]map[string]string{
	2: {"en": "half as much", "ko": "1/2만 반영"},
	3: {"en": "a third as much", "ko": "1/3만 반영"},
	4: {"en": "a quarter as much", "ko": "1/4만 반영"},
	8: {"en": "an eighth as much", "ko": "1/8만 반영"},
}

// axisScoreWith returns the score of the axis one finding lands on. The
// scoring constants are unexported and in another package, so the way to
// read them is to ask the scorer what it does — which is also the claim the
// prose actually makes, rather than an arithmetic identity standing in for it.
func axisScoreWith(t *testing.T, rem model.RemediationKind) int {
	t.Helper()
	f := model.NewFinding("ssh.probe", "t", model.SeverityExposed, model.SourceSSH, rem)
	for _, ax := range model.ScoreReport([]model.Finding{f}, nil).Axes {
		if ax.Source == model.SourceSSH {
			return int(ax.Score)
		}
	}
	t.Fatal("no ssh axis in a scored report")
	return 0
}

// TestScoringProseTripwire cannot read prose, so it watches what the prose
// describes. Changing the scoring model without touching the docs leaves four
// pages quietly lying about how the score works; this makes that a build
// failure with a pointer to what to edit.
//
// It asks the scorer rather than multiplying two constants together. The
// previous version asserted SeverityExposed.Penalty()*2 == 16, which reads
// as "one Critical costs half" but never touches criticalHalves — the
// denominator that decides it. Doubling that constant halves every finding's
// weight, the docs' "half" becomes a quarter on every page, and this passed.
func TestScoringProseTripwire(t *testing.T) {
	// "One Critical takes half of whatever an axis has left."
	full := axisScoreWith(t, model.RemediationAuto)
	if full != 50 {
		t.Errorf("one Exposed finding now leaves an axis at %d, not 50; docs in "+
			"content/{en,ko}/docs/{scoring,checks,faq}.html say \"half\" and need rewriting", full)
	}

	// "…counts a quarter as much" — the same finding with nothing that can
	// fix it. Derived from the erosion rather than the score, because the
	// relieved score is not a round number for every divisor.
	relieved := axisScoreWith(t, model.RemediationUnavailable)
	if relieved <= full || relieved >= 100 {
		t.Fatalf("an Unavailable Critical scored %d against %d — the relief is gone or inverted", relieved, full)
	}
	relief := int(math.Round(float64(100-full) / float64(100-relieved)))
	phrases, known := reliefProse[relief]
	if !known {
		t.Fatalf("the Unavailable relief is now 1/%d and reliefProse has no phrase for it; "+
			"add one and write it into content/{en,ko}/docs/checks.html", relief)
	}
	for _, lang := range docLangs {
		if !strings.Contains(checksPage(t, lang), phrases[lang]) {
			t.Errorf("%s: checks page does not state the Unavailable relief as %q "+
				"(the constant makes it 1/%d); content/%s/docs/scoring.html states it too",
				lang, phrases[lang], relief, lang)
		}
	}
}

// TestEverySeverityChipNamesARealLevel is the guard the severity column never
// had.
//
// Two tests read the finding table and neither looked at this cell:
// findingRow captures the last column (the fix kind) and weightRow avoids the
// severity table on purpose. So roughly a hundred and twenty cells across two
// languages restated a model enum with nothing checking the restatement — and
// when the four-level scale became three, a missed cell would have gone on
// naming a level that no longer exists, styled by a CSS class that no longer
// exists, which renders as unstyled text rather than as an error.
func TestEverySeverityChipNamesARealLevel(t *testing.T) {
	known := map[string]bool{}
	for _, s := range model.AllSeverities() {
		known[s.String()] = true
	}
	for _, lang := range docLangs {
		// Both pages that render severity chips. The scoring page carries a
		// dozen or more of its own and was not covered when it was added.
		chips := severityChip.FindAllStringSubmatch(checksPage(t, lang)+docsPage(t, lang, "scoring"), -1)
		if len(chips) == 0 {
			t.Fatalf("%s: no severity chips parsed; the markup changed", lang)
		}
		for _, c := range chips {
			class, text := c[1], c[2]
			if !known[class] {
				t.Errorf("%s: severity chip has class %q, which is not one of %v — "+
					"site/docs.css styles the levels by name, so this renders unstyled",
					lang, class, model.AllSeverities())
				continue
			}
			// The class and the word have to be the same level. A chip reading
			// EXPOSED in the colour of hardening is worse than either alone.
			if !strings.EqualFold(text, class) {
				t.Errorf("%s: severity chip is styled %q but reads %q", lang, class, text)
			}
		}
	}
}

// The severity a finding is documented at must be the same in both languages.
// Each is a separate file and nothing links them; the Fix column is already
// pinned this way, and the severity column is the other half of the same row.
func TestBothLanguagesAgreeOnSeverity(t *testing.T) {
	byLang := map[string]map[string]string{}
	for _, lang := range docLangs {
		byLang[lang] = map[string]string{}
		for _, row := range severityCell.FindAllStringSubmatch(checksPage(t, lang), -1) {
			var levels []string
			for _, c := range severityChip.FindAllStringSubmatch(row[2], -1) {
				levels = append(levels, c[1])
			}
			byLang[lang][row[1]] = strings.Join(levels, "/")
		}
		if len(byLang[lang]) == 0 {
			t.Fatalf("%s: no severity cells parsed; the markup changed", lang)
		}
	}
	for id, en := range byLang["en"] {
		ko, listed := byLang["ko"][id]
		if !listed {
			t.Errorf("ko: no severity cell for %s", id)
			continue
		}
		if en != ko {
			t.Errorf("%s is documented %s in English and %s in Korean", id, en, ko)
		}
	}
	for id := range byLang["ko"] {
		if _, listed := byLang["en"][id]; !listed {
			t.Errorf("en: no severity cell for %s", id)
		}
	}
}

// findingRef matches a finding ID cited in prose, wherever it appears.
var findingRef = func() *regexp.Regexp {
	names := make([]string, 0, len(model.AllSources()))
	for _, s := range model.AllSources() {
		names = append(names, regexp.QuoteMeta(s.String()))
	}
	return regexp.MustCompile(`<code>((?:` + strings.Join(names, "|") + `)\.[a-z0-9.\-]+)</code>`)
}()

// TestBothLanguagesCiteTheSameFindings is the parity guard for prose.
//
// TestBothLanguagesDocumentTheSameFindings covers the checks table, which is
// a table and drifts visibly. Prose does not: the fixing page argues its case
// through worked examples, and a language that quietly drops one — or cites a
// different one — is making a different argument with no way to notice. The
// two pages were written days apart by different hands and already differed
// on which compose finding illustrated the ambiguity criterion.
//
// It compares the whole docs tree, not one page, because every page that
// names a finding is making the same kind of claim about it.
func TestBothLanguagesCiteTheSameFindings(t *testing.T) {
	for _, page := range []string{"fixing", "scoring", "checks", "faq", "interfaces", "cli", "quickstart", "index", "troubleshooting", "ai", "installation", "contributing"} {
		cited := map[string][]string{}
		for _, lang := range docLangs {
			b, err := assets.ReadFile("content/" + lang + "/docs/" + page + ".html")
			if err != nil {
				continue // not every page exists in both trees by name
			}
			var ids []string
			for _, m := range findingRef.FindAllStringSubmatch(string(b), -1) {
				ids = append(ids, m[1])
			}
			slices.Sort(ids)
			cited[lang] = slices.Compact(ids)
		}
		if len(cited) != len(docLangs) {
			continue
		}
		if !slices.Equal(cited["en"], cited["ko"]) {
			t.Errorf("docs/%s cites different findings per language:\n en only: %v\n ko only: %v",
				page, missing(cited["en"], cited["ko"]), missing(cited["ko"], cited["en"]))
		}
	}
}

func missing(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// Every finding a docs page names in prose must be one a checker can emit.
// A worked example built on an ID that was renamed or retired is an argument
// about something that no longer happens, and it reads as authoritative.
//
// The scoring page is the one that matters most here: its worked example
// prints per-finding arithmetic, so a retired ID there is a sum a reader
// cannot reproduce.
func TestProseCitesOnlyRealFindings(t *testing.T) {
	documented := map[string]bool{}
	for _, row := range findingRow.FindAllStringSubmatch(checksPage(t, "en"), -1) {
		documented[row[1]] = true
	}
	// sysctl.d is a directory path, not a finding, and it is spelled the same
	// way. Anything else the pattern picks up has to be real.
	notAFinding := map[string]bool{"sysctl.d": true}

	for _, lang := range docLangs {
		for _, slug := range []string{"fixing", "scoring"} {
			for _, m := range findingRef.FindAllStringSubmatch(docsPage(t, lang, slug), -1) {
				if notAFinding[m[1]] || documented[m[1]] {
					continue
				}
				t.Errorf("%s: the %s page argues from %s, which the checks table does not list", lang, slug, m[1])
			}
		}
	}
}

// capTableRow matches a row of the scoring page's cap table: an axis label,
// its cap, and an argument cell. Anchored on three cells, because the funding
// tables on the same page are three-cell too and their middle column is also
// a number — a looser pattern reads point transfers as caps.
var capTableRow = regexp.MustCompile(`<tr><td>([^<]+)</td><td>(\d+)</td><td>`)

// TestScoringPageCapsMatchTheCode pins the second place the axis weights are
// written down.
//
// TestDocumentedAxisWeightsMatchTheCode covers the checks page and cannot
// cover this one: its weightRow pattern requires a two-cell row ending the
// <tr>, and these rows carry an argument column. So the twelve caps could
// drift from sourceDefs here with a green build — on the page that presents
// itself as the whole model, which is the worst place for them to be wrong.
//
// It reads the table by its id rather than the whole page, because the same
// page carries two funding tables whose middle column is a point count.
func TestScoringPageCapsMatchTheCode(t *testing.T) {
	var want []int
	total := 0
	for _, ax := range model.ScoreReport(nil, nil).Axes {
		want = append(want, ax.MaxPenalty)
		total += ax.MaxPenalty
	}
	slices.Sort(want)

	for _, lang := range docLangs {
		page := docsPage(t, lang, "scoring")
		start := strings.Index(page, `id="cap-table"`)
		if start < 0 {
			t.Fatalf("%s: the scoring page has no cap table (looked for id=\"cap-table\")", lang)
		}
		table := page[start:]
		if end := strings.Index(table, "</table>"); end >= 0 {
			table = table[:end]
		}

		var got []int
		for _, row := range capTableRow.FindAllStringSubmatch(table, -1) {
			n, err := strconv.Atoi(row[2])
			if err != nil {
				continue
			}
			got = append(got, n)
		}
		slices.Sort(got)

		// The Total row is part of the table and is the claim most worth
		// checking — it is the one number a reader will take on trust.
		if !strings.Contains(table, ">"+strconv.Itoa(total)+"<") {
			t.Errorf("%s: the scoring page's cap table does not state the total %d", lang, total)
		}
		var caps []int
		for _, n := range got {
			if n != total {
				caps = append(caps, n)
			}
		}
		if !slices.Equal(caps, want) {
			t.Errorf("%s: the scoring page documents axis weights %v, the code has %v", lang, caps, want)
		}
	}
}

// exactFigure matches a number written out to four or more decimal places —
// the kind that only appears because someone computed it.
var exactFigure = regexp.MustCompile(`\b\d+\.\d{4,}\b`)

// TestBothLanguagesPrintTheSameFigures pins the scoring page's arithmetic
// across languages.
//
// That page is the one place in the docs that shows its working: a worked
// example from a real scan, erosion step by step, exact dyadic decimals like
// 0.1922607421875, and a renormalized overall. A translation that recomputed
// anything, rounded differently, or quietly dropped a step would be a second
// arithmetic claiming to be the first, and prose parity tests would not see
// it — the sentences around it can differ freely.
//
// The first draft pair diverged exactly this way and had to be rewritten.
func TestBothLanguagesPrintTheSameFigures(t *testing.T) {
	figures := map[string][]string{}
	for _, lang := range docLangs {
		f := exactFigure.FindAllString(docsPage(t, lang, "scoring"), -1)
		slices.Sort(f)
		figures[lang] = slices.Compact(f)
	}
	if len(figures["en"]) < 15 {
		t.Fatalf("only %d exact figures found on the English scoring page — the worked "+
			"example is gone, or this pattern no longer matches it", len(figures["en"]))
	}
	if !slices.Equal(figures["en"], figures["ko"]) {
		t.Errorf("the scoring page prints different figures per language:\n en only: %v\n ko only: %v",
			missing(figures["en"], figures["ko"]), missing(figures["ko"], figures["en"]))
	}
}

// The two language trees must carry the same set of doc pages. A page added
// to one and not the other is a hole a reader falls into from the sidebar,
// which is generated from the manifest and so lists it in both.
func TestBothLanguagesHaveEveryDocsPage(t *testing.T) {
	pages := map[string][]string{}
	for _, lang := range docLangs {
		entries, err := assets.ReadDir("content/" + lang + "/docs")
		if err != nil {
			t.Fatalf("read %s docs dir: %v", lang, err)
		}
		for _, e := range entries {
			pages[lang] = append(pages[lang], e.Name())
		}
		slices.Sort(pages[lang])
	}
	if !slices.Equal(pages["en"], pages["ko"]) {
		t.Errorf("the language trees hold different pages:\n en only: %v\n ko only: %v",
			missing(pages["en"], pages["ko"]), missing(pages["ko"], pages["en"]))
	}
}

// A docs page's <h1> either is its sidebar label or is deliberately longer
// than it — docs/index is headed "hostveil documentation" under a nav of
// "Introduction", and the FAQ spells its acronym out. What must not differ is
// which of those a page does in each language.
//
// The site search indexes every page under its *sidebar* label and shows that
// as the result title. A page whose heading matches in one language and not
// the other means a Korean reader and an English reader get different answers
// to "did I land where I clicked", from the same page. The scoring page
// arrived exactly that way: aligned in Korean, descriptive in English.
//
// docs/faq is the one page allowed to differ, and the reason is that English
// has an acronym here and Korean does not: "FAQ" in the sidebar expanding to
// "Frequently asked questions" as the heading is the right pair, and there is
// no Korean equivalent of that move — 자주 묻는 질문 is the whole phrase either
// way. Any other page differing is drift.
var navHeadingExceptions = map[string]string{
	"faq": "English abbreviates in the sidebar and expands in the heading; Korean has no acronym to abbreviate",
}

func TestHeadingsAndNavLabelsAgreeAcrossLanguages(t *testing.T) {
	h1 := regexp.MustCompile(`<h1>([^<]*)</h1>`)
	unescape := strings.NewReplacer("&amp;", "&", "&rsquo;", "\u2019").Replace

	var m Manifest
	raw, err := assets.ReadFile("pages.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Docs) == 0 {
		t.Fatal("the manifest lists no docs pages")
	}

	for _, doc := range m.Docs {
		matches := map[string]bool{}
		for _, lang := range docLangs {
			nav := doc.En.Nav
			if lang == "ko" {
				nav = doc.Ko.Nav
			}
			found := h1.FindStringSubmatch(docsPage(t, lang, doc.Slug))
			if found == nil {
				t.Errorf("%s: docs/%s has no <h1>", lang, doc.Slug)
				continue
			}
			matches[lang] = unescape(found[1]) == nav
		}
		if _, allowed := navHeadingExceptions[doc.Slug]; allowed {
			if matches["en"] == matches["ko"] {
				t.Errorf("docs/%s no longer differs across languages — drop its "+
					"navHeadingExceptions entry so the check applies to it again", doc.Slug)
			}
			continue
		}
		if len(matches) == len(docLangs) && matches["en"] != matches["ko"] {
			t.Errorf("docs/%s is headed by its nav label in one language and not the other "+
				"(en=%v, ko=%v) — a search hit reads the nav label, so the two readers get "+
				"different answers to whether they landed where they clicked",
				doc.Slug, matches["en"], matches["ko"])
		}
	}
}
