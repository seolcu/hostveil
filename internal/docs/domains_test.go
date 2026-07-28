// The domain tables are the answer to "what does this thing actually
// look at", and there are three of them: README.md's "What it checks",
// and the "Domains at a glance" table on the docs site in both languages.
// All three are prose, and all three restate a list the code owns.
//
// They went stale exactly as prose does. The AI agent runtimes domain
// shipped in 3.5.0 and kernel hardening was the headline of 3.6.0, and
// README advertised eight of ten domains through both releases — the two
// missing ones being the newest, which is the worst possible pair to omit
// from the first thing a visitor reads. The site's table missed the tenth
// for a release too, while the very same page carried a full section about
// it further down.
//
// Same policy as the rest of this package: the label is prose and is not
// checked, but the finding-ID prefix each domain owns is mechanical, so
// that is what these assert.
package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// TestReadmeDocumentsEveryDomain pins README's table to model.AllSources.
//
// It matches on the prefix code span (`compose.*`) rather than the display
// name, because the name is prose an author may reword — "Docker /
// Compose", "Containers" — while the prefix is the string a user types
// into `hostveil fix`, and it is wrong or right.
func TestReadmeDocumentsEveryDomain(t *testing.T) {
	table := section(t, readRepoFile(t, "README.md"), "## What it checks", "## ")
	found := 0
	for _, src := range model.AllSources() {
		want := "`" + src.String() + ".*`"
		if !strings.Contains(table, want) {
			t.Errorf("README.md's domain table has no row for %s", want)
			continue
		}
		found++
	}
	if found < len(model.AllSources()) {
		return // the errors above already say which
	}
	// Nothing-extracted guard: an empty section would make every Contains
	// fail loudly, but a section that swallowed the whole file would make
	// them all pass. Both are extraction bugs, not doc bugs.
	if len(table) > len(readRepoFile(t, "README.md"))/2 {
		t.Fatalf("the extracted table is %d bytes of a %d-byte README — the section bounds are wrong",
			len(table), len(readRepoFile(t, "README.md")))
	}
}

// TestSiteDocumentsEveryDomain does the same for the generated site, in
// both languages. The Korean page is checked too because en/ko drift is
// its own failure: a Korean reader gets a table that quietly describes a
// smaller product.
func TestSiteDocumentsEveryDomain(t *testing.T) {
	for _, lang := range []string{"en", "ko"} {
		path := filepath.Join("cmd", "sitegen", "content", lang, "docs", "checks.html")
		body := readRepoFile(t, path)
		for _, src := range model.AllSources() {
			want := "<code>" + src.String() + ".</code>"
			if !strings.Contains(body, want) {
				t.Errorf("%s has no domain row for %s", path, want)
			}
		}
		// The site is generated, so the committed output must carry it too
		// — that is what the deploy actually serves.
		out := filepath.Join("site", langDir(lang), "docs", "checks.html")
		if _, err := os.Stat(filepath.Join(repoRoot(t), out)); err != nil {
			t.Fatalf("%s does not exist — the site layout moved and this test did not", out)
		}
		generated := readRepoFile(t, out)
		for _, src := range model.AllSources() {
			if want := "<code>" + src.String() + ".</code>"; !strings.Contains(generated, want) {
				t.Errorf("%s is missing %s — regenerate with `go run ./cmd/sitegen`", out, want)
			}
		}
	}
}

// langDir maps a content language to its path in the generated site. English
// is served from the root; every other language gets a subdirectory.
func langDir(lang string) string {
	if lang == "en" {
		return "."
	}
	return lang
}

// section returns the text between a heading and the next one at the same
// level, so a test can assert about one part of a document without matching
// the whole file.
func section(t *testing.T, doc, heading, nextPrefix string) string {
	t.Helper()
	i := strings.Index(doc, heading)
	if i < 0 {
		t.Fatalf("the document has no %q heading — it was renamed, and this test needs to know", heading)
	}
	rest := doc[i+len(heading):]
	if j := strings.Index(rest, "\n"+nextPrefix); j >= 0 {
		return rest[:j]
	}
	return rest
}
