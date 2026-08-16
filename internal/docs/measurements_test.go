package docs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The measured-results page publishes numbers that came off a real host, and
// a published number is the one kind of documentation that cannot be checked
// by reading it. A stale figure looks exactly like a fresh one — more so
// here than anywhere else on the site, because the whole argument of the
// page is that these are measurements rather than claims.
//
// So every figure on the page carries the JSON path it came from:
//
//	<td data-measured="phases.before.lynis.hardening_index">57</td>
//
// and this test resolves that path in the committed run under
// docs/measurements/ and requires the rendered text to match. Re-running the
// harness and committing a new result therefore fails the build until the
// page is updated, which is the only order in which those two can be trusted
// to agree.
//
// It reads the *newest* committed run by filename, which is also the one the
// page is supposed to describe. Older runs stay in the directory as a record
// and are not checked against anything: they are what the host looked like
// then.
var measuredCell = regexp.MustCompile(`<[^<>]*data-measured="([^"]+)"[^<>]*>([^<]*)<`)

// runAttr names the run a figure came off, when it is not the newest one.
//
//	<td data-measured-run="2026-08-14-seeded-fedora.json"
//	    data-measured="phases.before.hostveil.overall">41</td>
//
// One run was enough while the page described one host. It cannot describe
// what changes across distributions from a single file, and the alternative —
// citing the extra runs in prose — puts the figures nobody checks right beside
// the figures somebody does, which is worse than not publishing them.
//
// It is read out of the tag measuredCell matched rather than by a pattern of
// its own, so the two attributes may be written in either order. A pattern
// requiring one order would not fail on the other one: it would fall through
// to the default and check a Fedora figure against the Debian run, which is
// the quiet kind of wrong this file exists to prevent.
//
// Opt-in, so a page that says nothing about runs is still pinned to the
// newest one exactly as before.
var runAttr = regexp.MustCompile(`data-measured-run="([^"]+)"`)

// runOf returns the run a matched cell names, or "" for the newest.
func runOf(tag string) string {
	if m := runAttr.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	return ""
}

func newestMeasurement(t *testing.T) (string, map[string]any) {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "docs", "measurements")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("docs/measurements/ holds no committed run, so the page's figures rest on nothing")
	}
	// Newest by the run's own measured_at, not by filename. Filename order
	// was the rule and it is a trap: a second run on one day sorts *before*
	// the first, because "…-arm64-v3.13.json" and "…-arm64.json" first differ
	// at '-' against '.', and '-' is the smaller byte. The page would then be
	// pinned against the older run while every number on it came from the
	// newer one, and the failure would read as a page that cites figures no
	// run supports.
	sort.Strings(names)
	var name string
	var doc map[string]any
	var newest time.Time
	for _, n := range names {
		var d map[string]any
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("%s is not valid JSON: %v", n, err)
		}
		s, _ := d["measured_at"].(string)
		at, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("%s has no parseable measured_at (%q): a run that cannot say when it "+
				"ran cannot be ordered against the others", n, s)
		}
		// Not-after, so ties keep the lexicographically last — the old rule,
		// which is as good an answer as any when two runs claim one instant.
		if name == "" || !at.Before(newest) {
			name, doc, newest = n, d, at
		}
	}
	return name, doc
}

// resolve walks a dotted path through the decoded JSON. A path segment that
// is all digits indexes an array, so a list of ports can be cited by
// position.
func resolveJSON(doc any, path string) (any, error) {
	cur := doc
	for _, part := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[part]
			if !ok {
				return nil, fmt.Errorf("no key %q", part)
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				return nil, fmt.Errorf("no index %q in a list of %d", part, len(node))
			}
			cur = node[i]
		default:
			return nil, fmt.Errorf("cannot descend into %T at %q", cur, part)
		}
	}
	return cur, nil
}

// render turns a JSON value into the text a page would write for it.
// Numbers come back from encoding/json as float64, and an integer written as
// "57.0" would fail against a page that sensibly says 57.
func renderJSON(v any) string {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return strconv.FormatInt(int64(n), 10)
		}
		return strconv.FormatFloat(n, 'f', -1, 64)
	case string:
		return n
	case bool:
		return strconv.FormatBool(n)
	case nil:
		return "N/A"
	case []any:
		parts := make([]string, 0, len(n))
		for _, e := range n {
			parts = append(parts, renderJSON(e))
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprint(v)
}

func measuredPage(t *testing.T, lang string) string {
	t.Helper()
	return readRepoFile(t, filepath.Join("cmd", "sitegen", "content", lang, "docs", "measurements.html"))
}

func TestEveryPublishedFigureCameOffTheCommittedRun(t *testing.T) {
	name, doc := newestMeasurement(t)

	for _, lang := range []string{"en", "ko"} {
		page := measuredPage(t, lang)
		cells := measuredCell.FindAllStringSubmatch(page, -1)
		if len(cells) == 0 {
			t.Fatalf("%s/measurements.html cites no figure at all — every number on that page "+
				"must carry data-measured, or none of them is checked", lang)
		}
		for _, c := range cells {
			path, shown := c[1], strings.TrimSpace(c[2])
			// Cells naming their own run are checked below, against that run.
			if runOf(c[0]) != "" {
				continue
			}
			want, err := resolveJSON(doc, path)
			if err != nil {
				t.Errorf("%s: data-measured=%q does not resolve in %s: %v", lang, path, name, err)
				continue
			}
			// The page may write "—" for a value it is only marking as
			// unchanged; anything else has to be the measurement itself.
			if got := renderJSON(want); got != shown && shown != "—" {
				t.Errorf("%s: the page says %q for %s, and %s records %q",
					lang, shown, path, name, got)
			}
		}
	}
}

// TestEveryFigureNamingItsOwnRunCameOffThatRun is the same guarantee for the
// figures that describe a host other than the one the page leads with.
//
// A cross-distribution result is several runs published side by side, and the
// pin has to follow each figure to the file it came from — otherwise the
// Fedora column is checked against the Debian run, which either fails for no
// reason or, where the numbers happen to agree, passes without looking.
func TestEveryFigureNamingItsOwnRunCameOffThatRun(t *testing.T) {
	loaded := map[string]map[string]any{}

	for _, lang := range []string{"en", "ko"} {
		for _, c := range measuredCell.FindAllStringSubmatch(measuredPage(t, lang), -1) {
			run := runOf(c[0])
			if run == "" {
				continue
			}
			path, shown := c[1], strings.TrimSpace(c[2])
			doc, seen := loaded[run]
			if !seen {
				b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "measurements", run))
				if err != nil {
					t.Errorf("%s: the page cites %s, which is not committed under docs/measurements/: %v",
						lang, run, err)
					loaded[run] = nil
					continue
				}
				if err := json.Unmarshal(b, &doc); err != nil {
					t.Errorf("%s: %s does not parse: %v", lang, run, err)
					loaded[run] = nil
					continue
				}
				loaded[run] = doc
			}
			if doc == nil {
				continue
			}
			want, err := resolveJSON(doc, path)
			if err != nil {
				t.Errorf("%s: data-measured=%q does not resolve in %s: %v", lang, path, run, err)
				continue
			}
			if got := renderJSON(want); got != shown && shown != "—" {
				t.Errorf("%s: the page says %q for %s in %s, and that run records %q",
					lang, shown, path, run, got)
			}
		}
	}
}

// And both languages must cite the same figures. The Korean page is a
// translation of an argument about numbers, so a figure updated on one and
// not the other is the same staleness this file exists to catch, arriving
// through the door that is easiest to forget.
func TestBothLanguagesCiteTheSameFigures(t *testing.T) {
	paths := map[string][]string{}
	for _, lang := range []string{"en", "ko"} {
		for _, c := range measuredCell.FindAllStringSubmatch(measuredPage(t, lang), -1) {
			// Keyed by run as well as path. Once the page publishes several
			// hosts, the same JSON path appears once per distribution, and
			// comparing paths alone would call a page citing Fedora's score
			// equal to one citing Alpine's.
			key := c[1]
			if run := runOf(c[0]); run != "" {
				key = run + " " + key
			}
			paths[lang] = append(paths[lang], key)
		}
		slices.Sort(paths[lang])
		paths[lang] = slices.Compact(paths[lang])
	}
	for _, p := range paths["en"] {
		if !slices.Contains(paths["ko"], p) {
			t.Errorf("the English page cites %s and the Korean page does not", p)
		}
	}
	for _, p := range paths["ko"] {
		if !slices.Contains(paths["en"], p) {
			t.Errorf("the Korean page cites %s and the English page does not", p)
		}
	}
}

// The claim the whole page rests on. If the committed run shows a file that
// did not come back, the page must not be published saying rollback is
// exact — and the number of files it changed has to be more than zero, or
// "restored every one of them" is a statement about the empty set.
func TestTheCommittedRunActuallyRestoredTheHost(t *testing.T) {
	name, doc := newestMeasurement(t)

	for path, want := range map[string]float64{
		"rollback.paths_changed_by_fixes": 1, // at least
		"rollback.fidelity":               100,
	} {
		v, err := resolveJSON(doc, path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n, ok := v.(float64)
		if !ok {
			t.Fatalf("%s: %s is %T, not a number", name, path, v)
		}
		if n < want {
			t.Errorf("%s records %s = %v, and the page publishes rollback as exact", name, path, v)
		}
	}

	for _, path := range []string{
		"rollback.paths_not_restored",
		"rollback.paths_with_unobserved_before_state",
		"fixes.failed",
	} {
		v, err := resolveJSON(doc, path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if list, ok := v.([]any); ok && len(list) > 0 {
			t.Errorf("%s records %s = %v", name, path, list)
		}
	}
}

// TestTheRunAttributeActuallyMatches proves the mechanism before anything
// depends on it.
//
// Nothing on the page carries data-measured-run yet, so the test above passes
// without resolving a single figure. A pin that has never matched anything is
// indistinguishable from a pin that does not work, and this repository has
// already shipped one: e2e.yml selected domains on an enum's old integer,
// matched nothing after the encoding changed to names, and its assertion
// passed on every pull request without once looking at a domain.
func TestTheRunAttributeActuallyMatches(t *testing.T) {
	cases := []struct {
		name, cell, wantRun, wantPath, wantText string
	}{
		{
			name:     "run first",
			cell:     `<td data-measured-run="2026-08-14-seeded-fedora.json" data-measured="phases.before.hostveil.overall">41</td>`,
			wantRun:  "2026-08-14-seeded-fedora.json",
			wantPath: "phases.before.hostveil.overall",
			wantText: "41",
		},
		{
			// Both orders, because a page author will write both and the one
			// that is not matched fails silently rather than loudly.
			name:     "run second",
			cell:     `<td data-measured="phases.after.lynis.hardening_index" data-measured-run="2026-08-14-seeded-alpine.json">63</td>`,
			wantRun:  "2026-08-14-seeded-alpine.json",
			wantPath: "phases.after.lynis.hardening_index",
			wantText: "63",
		},
		{
			name:     "no run names the newest",
			cell:     `<td data-measured="phases.before.hostveil.overall">40</td>`,
			wantRun:  "",
			wantPath: "phases.before.hostveil.overall",
			wantText: "40",
		},
		{
			name:     "a span, not only a cell",
			cell:     `<span data-measured="phases.reviewed.hostveil.axes.ssh">100</span>`,
			wantRun:  "",
			wantPath: "phases.reviewed.hostveil.axes.ssh",
			wantText: "100",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := measuredCell.FindStringSubmatch(tc.cell)
			if m == nil {
				t.Fatal("the pattern does not match the markup the page is told to write")
			}
			if got := runOf(m[0]); got != tc.wantRun {
				t.Errorf("run = %q, want %q", got, tc.wantRun)
			}
			if m[1] != tc.wantPath {
				t.Errorf("path = %q, want %q", m[1], tc.wantPath)
			}
			if strings.TrimSpace(m[2]) != tc.wantText {
				t.Errorf("text = %q, want %q", m[2], tc.wantText)
			}
		})
	}
}

// TestNoPublishedFigureIsEmpty rejects a pin that cannot fail.
//
// renderJSON returns "" for an empty list, and an empty cell shows "" too, so
// the two match and the assertion passes without looking at anything. That is
// how this page came to carry the sentence "the suggestion it cleared is
// attributable: <code data-measured="deltas.lynis_suggestions.reviewed.cleared">
// </code>, detect toolkit to…" against a run that cleared no suggestion at all:
// the newest run records an empty list there, the element rendered blank, and
// the claim around it went on being made for two releases.
//
// It is the same defect as the CI selector in 3.14.1 that matched no domain
// after the enum changed encoding and passed on every pull request. A check
// whose subject is absent is not a check.
//
// A figure that is genuinely empty — a list of nothing, a count of zero
// occurrences — belongs in prose, or as the count rather than the contents.
func TestNoPublishedFigureIsEmpty(t *testing.T) {
	name, doc := newestMeasurement(t)

	for _, lang := range []string{"en", "ko"} {
		for _, c := range measuredCell.FindAllStringSubmatch(measuredPage(t, lang), -1) {
			path := c[1]
			if runOf(c[0]) != "" {
				continue
			}
			want, err := resolveJSON(doc, path)
			if err != nil {
				continue // the test above reports an unresolvable path
			}
			if renderJSON(want) == "" {
				t.Errorf("%s: data-measured=%q renders as nothing against %s, so the "+
					"sentence around it is claiming something no test can check. "+
					"Say it in prose, or cite a count instead of the contents.",
					lang, path, name)
			}
		}
	}
}

// archWords are the ways this page could name an architecture.
var archWords = regexp.MustCompile(`(?i)\b(arm64|aarch64|x86[_-]?64|amd64)\b`)

// TestThePageOnlyNamesAnArchitectureTheRunRecorded closes the last unpinned
// claim on this page.
//
// It read "An ARM64 server seeded with…" for four published runs, and no run
// carried an architecture at all — `host` held id, kernel, pretty_name and
// version_id, and nothing else. The word came out of the filename, which is
// to say out of whoever typed the filename. Every other figure here resolves
// against the committed JSON; this one asserted a hardware fact from prose.
//
// The harness records `arch` now (scripts/measure/report.py), so the sentence
// can come back the moment a run carries one. Until then the page does not
// say it, because "we could not tell" and "it was ARM64" are different
// statements and only one of them was measured.
//
// The committed runs were deliberately left alone. Adding `arch` to them by
// hand would be inventing measurement output, which is the failure this whole
// page exists to argue against.
func TestThePageOnlyNamesAnArchitectureTheRunRecorded(t *testing.T) {
	name, doc := newestMeasurement(t)
	recorded, err := resolveJSON(doc, "host.arch")
	got := ""
	if err == nil {
		got = strings.ToLower(renderJSON(recorded))
	}

	for _, lang := range []string{"en", "ko"} {
		// Through proseOnly for the reason given there: the rule is about
		// what the page tells a reader, and a run cited by filename puts an
		// architecture in an attribute without claiming anything.
		for _, m := range archWords.FindAllString(proseOnly(measuredPage(t, lang)), -1) {
			word := strings.ToLower(m)
			switch {
			case got == "":
				t.Errorf("%s: the page says %q and %s records no host.arch at all — "+
					"either the run has to carry it or the page must not name one",
					lang, m, name)
			case !sameArch(word, got):
				t.Errorf("%s: the page says %q and %s recorded %q", lang, m, name, got)
			}
		}
	}
}

// sameArch treats the spellings of one machine as one machine. uname reports
// aarch64 and x86_64; prose says arm64 and amd64, and a page failing over
// that difference would be failing over vocabulary rather than over a claim.
func sameArch(word, recorded string) bool {
	group := func(s string) string {
		switch strings.ToLower(strings.ReplaceAll(s, "-", "_")) {
		case "arm64", "aarch64":
			return "arm"
		case "x86_64", "x8664", "amd64":
			return "x86"
		}
		return s
	}
	return group(word) == group(recorded)
}
