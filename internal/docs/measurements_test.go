package docs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Every measured figure on the site carries the JSON path it came from:
//
//	<td data-measured="phases.before.lynis.hardening_index">57</td>
//
// and is resolved against the committed run under docs/measurements/. A cell
// may name its run with data-measured-run; otherwise it is the newest run of
// a published profile, by measured_at. Committing a new run therefore fails
// the build until the pages are updated.
var (
	measuredCell = regexp.MustCompile(`<[^<>]*data-measured="([^"]+)"[^<>]*>([^<]*)<`)
	runAttr      = regexp.MustCompile(`data-measured-run="([^"]+)"`)
)

// publishedProfiles are the seeded experiments the site describes. Control
// runs and summaries have other schemas and are never selected.
var publishedProfiles = []string{"seeded", "cisc-w2026-seeded-v2"}

func loadRun(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "measurements", name))
	if err != nil {
		t.Fatalf("read run %s: %v", name, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s is not valid JSON: %v", name, err)
	}
	return doc
}

func newestMeasurement(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), "docs", "measurements"))
	if err != nil {
		t.Fatal(err)
	}
	var name string
	var newest time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		d := loadRun(t, e.Name())
		if pr, _ := d["profile"].(string); !slices.Contains(publishedProfiles, pr) {
			continue
		}
		s, _ := d["measured_at"].(string)
		at, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("%s has no parseable measured_at (%q)", e.Name(), s)
		}
		if name == "" || !at.Before(newest) {
			name, newest = e.Name(), at
		}
	}
	if name == "" {
		t.Fatalf("docs/measurements/ holds no run with a published profile %q", publishedProfiles)
	}
	return name
}

func TestEveryMeasuredFigureCameOffTheCommittedRun(t *testing.T) {
	newest := newestMeasurement(t)
	runs := map[string]map[string]any{}
	seen := 0
	for _, page := range []string{"index.html", filepath.Join("docs", "measurements.html")} {
		for _, lang := range []string{"en", "ko"} {
			rel := filepath.Join("cmd", "sitegen", "content", lang, page)
			for _, c := range measuredCell.FindAllStringSubmatch(readRepoFile(t, rel), -1) {
				run := newest
				if m := runAttr.FindStringSubmatch(c[0]); m != nil {
					run = m[1]
				}
				if runs[run] == nil {
					runs[run] = loadRun(t, run)
				}
				path, shown := c[1], strings.TrimSpace(c[2])
				want, err := resolveJSON(runs[run], path)
				if err != nil {
					t.Errorf("%s: data-measured=%q does not resolve in %s: %v", rel, path, run, err)
					continue
				}
				seen++
				// "—" marks a value the page shows only as unchanged.
				if got := renderJSON(want); got != shown && shown != "—" {
					t.Errorf("%s says %q for %s, and %s records %q", rel, shown, path, run, got)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no page carries a data-measured cell, so this test proves nothing")
	}
}

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
