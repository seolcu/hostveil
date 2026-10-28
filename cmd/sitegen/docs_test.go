package main

import (
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
	// <span class="sev high">HIGH</span>, wherever one appears.
	severityChip = regexp.MustCompile(`<span class="sev ([a-z\-]+)">([^<]*)</span>`)
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

// checkerAsksForMore records the findings whose documented kind is stricter
// than the registry can show from a representative finding, and why.
//
// It used to hold every fix a checker always declares Review for. Those now
// live in fix.checkerDeclaresReview, which the registry applies, so the
// registry reports the kind a user is shown and this list does not have to
// repeat it. What is left is the case the registry cannot settle on its own:
// agent.exec-unrestricted reads its safe values out of the finding, so how
// many alternatives it has — and so whether it is Review — depends on which
// config key tripped, and fixtest builds a finding carrying neither.
var checkerAsksForMore = map[string]string{
	"agent.exec-unrestricted": "deny and ask are both correct and the operator picks, so the checker declares Review whenever tools.exec.security is what tripped",
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

// The CLI reference documents the exact strings `scan --json` can put in
// each enumerated field, and that sentence is a contract: somebody is
// writing a `jq` filter against it.
//
// It went stale silently. The severity levels were renamed and the page went
// on listing the previous names — beside a sample payload that also carried
// one — while the prose two paragraphs up had already been updated, so the
// page contradicted itself and still built green. Nothing read these values
// because they are prose in a <code> tag rather than a table row.
func TestTheDocumentedJSONValuesAreTheOnesTheModelEmits(t *testing.T) {
	for _, lang := range docLangs {
		page := docsPage(t, lang, "cli")
		for _, want := range jsonEnumNames() {
			if !strings.Contains(page, "<code>"+want+"</code>") {
				t.Errorf("%s cli reference does not list %q as a `scan --json` value, "+
					"and the encoder emits it", lang, want)
			}
		}
		// And nothing a previous release emitted, which is what makes this a
		// tripwire rather than a spell-checker: a name that only survives in
		// the legacy read path must not be documented as output.
		for _, gone := range []string{"exposed", "weak", "hardening", "critical"} {
			if strings.Contains(page, "<code>"+gone+"</code>") {
				t.Errorf("%s cli reference still documents %q as a `scan --json` value; "+
					"Hostveil reads that name but has not written it since it was renamed", lang, gone)
			}
		}
	}
}

// jsonEnumNames is every name the enumerated fields of `scan --json` can
// hold, taken from the model rather than restated.
func jsonEnumNames() []string {
	var out []string
	for _, s := range model.AllSeverities() {
		out = append(out, s.String())
	}
	for _, k := range model.AllRemediationKinds() {
		if k == model.RemediationUnset {
			continue // never reaches a validated finding
		}
		out = append(out, k.String())
	}
	return out
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
			// HIGH in the colour of low is worse than either alone.
			if !strings.EqualFold(text, class) {
				t.Errorf("%s: severity chip is styled %q but reads %q", lang, class, text)
			}
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
