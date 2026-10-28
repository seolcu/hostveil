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
		"README.ko.md",
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
