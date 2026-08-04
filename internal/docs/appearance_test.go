// The two appearance registries — color themes and terminal symbol sets —
// are named out loud in six documents: README, the `hostveil help` text
// compiled into the binary, and the Interfaces and CLI-reference pages of
// the docs site in both languages. Every one of those is prose restating a
// list the code owns, which is the shape this package exists to guard.
//
// It has already gone wrong once in the direction a spelled-out list cannot
// catch on its own. The Instrument theme was deleted and One Dark became the
// default; `hostveil help` went on offering "instrument (default)" to
// everyone who asked, naming a theme the binary would refuse. Nothing failed,
// because every *remaining* theme was still listed — the stale entry was an
// extra, and an extra is invisible to a test that only checks for presence.
//
// So these check both directions: every registered ID appears, and the count
// the prose states is the count the registry has. A removed theme leaves the
// second one wrong even while the first still passes.
package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/glyph"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

// appearanceDocs are the files that name these lists, source and generated.
// The generated pages are included for the same reason the domain test
// includes them: site/ is what the deploy actually serves, and a content
// edit that was never regenerated reaches nobody.
func appearanceDocs(t *testing.T) map[string]string {
	t.Helper()
	paths := []string{
		"README.md",
		filepath.Join("cmd", "hostveil", "main.go"),
	}
	for _, lang := range []string{"en", "ko"} {
		for _, page := range []string{"interfaces.html", "cli.html"} {
			paths = append(paths,
				filepath.Join("cmd", "sitegen", "content", lang, "docs", page),
				filepath.Join("site", langDir(lang), "docs", page))
		}
	}
	out := make(map[string]string, len(paths))
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(repoRoot(t), p)); err != nil {
			t.Fatalf("%s does not exist — a file moved and this test did not", p)
		}
		out[p] = readRepoFile(t, p)
	}
	return out
}

// TestDocumentedThemesMatchTheRegistry pins every document that lists theme
// IDs to theme.IDs(). The ID is the string a user types after --theme, so
// unlike a display name it is wrong or right.
func TestDocumentedThemesMatchTheRegistry(t *testing.T) {
	for path, body := range appearanceDocs(t) {
		for _, id := range theme.IDs() {
			if !strings.Contains(body, id) {
				t.Errorf("%s does not name the %q theme", path, id)
			}
		}
	}
}

// TestDocumentedGlyphSetsMatchTheRegistry does the same for --glyphs. The
// list is short enough that it looks safe to write out by hand, which is
// exactly how the theme list came to carry a name the binary had dropped.
func TestDocumentedGlyphSetsMatchTheRegistry(t *testing.T) {
	for path, body := range appearanceDocs(t) {
		for _, id := range glyph.IDs() {
			if !strings.Contains(body, id) {
				t.Errorf("%s does not name the %q symbol set", path, id)
			}
		}
	}
}

// TestTheDefaultThemeIsDocumentedAsTheDefault covers the prose that says
// which one you get without asking. Only the three documents that make that
// claim are checked — the CLI reference states defaults in its own column
// and is covered by the presence test above.
func TestTheDefaultThemeIsDocumentedAsTheDefault(t *testing.T) {
	def := theme.Default().ID
	// The phrasings differ ("(the default)", "(default)", "(기본값)") and are
	// prose, so the assertion is only that the word follows the ID closely
	// enough to be about it.
	const window = 48
	for _, tc := range []struct{ path, word string }{
		{"README.md", "default"},
		{filepath.Join("cmd", "hostveil", "main.go"), "default"},
		{filepath.Join("cmd", "sitegen", "content", "en", "docs", "interfaces.html"), "default"},
		{filepath.Join("cmd", "sitegen", "content", "ko", "docs", "interfaces.html"), "기본값"},
	} {
		body := readRepoFile(t, tc.path)
		i := strings.Index(body, def)
		if i < 0 {
			t.Errorf("%s does not name the default theme %q at all", tc.path, def)
			continue
		}
		tail := body[i:min(len(body), i+window)]
		if !strings.Contains(tail, tc.word) {
			t.Errorf("%s names %q but does not call it the default: %q", tc.path, def, tail)
		}
	}
}

// koNumberWords is the Korean half; the English half is numberWords in
// agents_test.go, read backwards. A registry that grows past either table
// fails loudly here rather than silently going unchecked, which is the
// failure a lookup with a fallback would produce.
var koNumberWords = map[int]string{
	3: "세", 4: "네", 5: "다섯", 6: "여섯", 7: "일곱", 8: "여덟",
}

// numberWord spells n in the given language, or reports that neither table
// reaches that far.
func numberWord(lang string, n int) (string, bool) {
	if lang == "ko" {
		w, ok := koNumberWords[n]
		return w, ok
	}
	for word, v := range numberWords {
		if v == n {
			return word, true
		}
	}
	return "", false
}

// TestTheDocumentedThemeCountIsTheRealOne is the half of this that catches a
// *removal*. Deleting Instrument left "six color themes" written in three
// places while every remaining theme was still correctly listed, so nothing
// that only looked for what should be there could have noticed.
func TestTheDocumentedThemeCountIsTheRealOne(t *testing.T) {
	n := len(theme.All())
	for _, tc := range []struct{ path, lang, suffix string }{
		{"README.md", "en", " color themes"},
		{filepath.Join("cmd", "sitegen", "content", "en", "docs", "interfaces.html"), "en", " color themes"},
		{filepath.Join("cmd", "sitegen", "content", "en", "index.html"), "en", " color themes"},
		{filepath.Join("cmd", "sitegen", "content", "ko", "docs", "interfaces.html"), "ko", " 가지 색상 테마"},
		{filepath.Join("cmd", "sitegen", "content", "ko", "index.html"), "ko", " 가지 색상 테마"},
	} {
		word, ok := numberWord(tc.lang, n)
		if !ok {
			t.Fatalf("there are now %d themes and there is no %s word for it — extend the table", n, tc.lang)
		}
		body := readRepoFile(t, tc.path)
		if want := word + tc.suffix; !strings.Contains(body, want) {
			t.Errorf("%s does not say %q — the theme registry has %d entries", tc.path, want, n)
		}
	}
}
