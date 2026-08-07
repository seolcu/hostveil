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
var measuredCell = regexp.MustCompile(`data-measured="([^"]+)"[^>]*>([^<]*)<`)

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

// And both languages must cite the same figures. The Korean page is a
// translation of an argument about numbers, so a figure updated on one and
// not the other is the same staleness this file exists to catch, arriving
// through the door that is easiest to forget.
func TestBothLanguagesCiteTheSameFigures(t *testing.T) {
	paths := map[string][]string{}
	for _, lang := range []string{"en", "ko"} {
		for _, c := range measuredCell.FindAllStringSubmatch(measuredPage(t, lang), -1) {
			paths[lang] = append(paths[lang], c[1])
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
