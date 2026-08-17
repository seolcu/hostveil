package docs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The Korean site is set in a webfont, and a webfont built by subsetting is
// the one kind of asset that is wrong silently.
//
// Neither Georgia nor the monospace stack has a Hangul glyph, so until
// site/korean.css existed every Korean character on the site was drawn by
// whatever the reader's machine fell back to — and on Fedora that was a
// *monospace* CJK face for every label, button, nav link and finding title,
// because the stack asked for "Noto Sans KR" (the Google Fonts name, which no
// distribution registers) and fell through to the generic at the end of a
// monospace list. The fix is the two faces scripts/korean-subset.py builds.
//
// They carry the site's own repertoire — 766 of Korean's 11,172 syllables,
// which is what gets a serif weight to 112KB instead of megabytes — and that
// is precisely the risk. Write one new Korean sentence containing one syllable
// that was not on the site when the subset was built, and nothing breaks:
// that single character falls back to a system font in the middle of a word,
// in a different face at a size nobody chose, and every other character around
// it is correct. It survives review, because a reviewer reads the diff of the
// copy and not the cmap of a binary, and it survives testing on any machine
// whose fallback happens to look close enough.
//
// So the script writes down what it built and this reads it back.

const koreanManifestPath = "site/assets/fonts/coverage.txt"

type koreanFont struct {
	name   string
	size   int64
	sha256 string
}

type koreanManifest struct {
	syllables map[rune]bool
	fonts     []koreanFont
}

// readKoreanManifest parses site/assets/fonts/coverage.txt: the `font` lines
// name what was built, and everything after the `codepoints N` line is the
// repertoire those files carry.
func readKoreanManifest(t *testing.T) koreanManifest {
	t.Helper()
	path := filepath.Join(repoRoot(t), koreanManifestPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v\n"+
			"  This is written by scripts/korean-subset.py alongside the woff2 files.\n"+
			"  Without it nothing can tell whether the Korean pages have a glyph for\n"+
			"  every syllable they use.", koreanManifestPath, err)
	}

	m := koreanManifest{syllables: map[rune]bool{}}
	var declared int
	var inRepertoire bool
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if inRepertoire {
			for _, r := range line {
				m.syllables[r] = true
			}
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "font":
			if len(fields) != 4 {
				t.Fatalf("%s: malformed font line %q", koreanManifestPath, line)
			}
			size, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				t.Fatalf("%s: %q has an unparseable size: %v", koreanManifestPath, line, err)
			}
			m.fonts = append(m.fonts, koreanFont{
				name:   fields[1],
				size:   size,
				sha256: strings.TrimPrefix(fields[3], "sha256:"),
			})
		case "codepoints":
			if declared, err = strconv.Atoi(fields[1]); err != nil {
				t.Fatalf("%s: %q has an unparseable count: %v", koreanManifestPath, line, err)
			}
			inRepertoire = true
		}
	}

	if declared == 0 || len(m.syllables) != declared {
		t.Fatalf("%s says it covers %d codepoints and lists %d.\n"+
			"  A manifest that does not agree with itself was edited by hand; re-run\n"+
			"  scripts/korean-subset.py.", koreanManifestPath, declared, len(m.syllables))
	}
	if len(m.fonts) == 0 {
		t.Fatalf("%s names no font files, so this test would pass against no fonts at all", koreanManifestPath)
	}
	return m
}

// hangulBlocks are the ranges site/korean.css declares as its unicode-range.
// A codepoint outside them is drawn by the Latin stack and needs no glyph here.
var hangulBlocks = [][2]rune{
	{0x1100, 0x11FF}, // Hangul Jamo
	{0x3130, 0x318F}, // Hangul Compatibility Jamo
	{0xA960, 0xA97F}, // Hangul Jamo Extended-A
	{0xAC00, 0xD7A3}, // Hangul Syllables
	{0xD7B0, 0xD7FF}, // Hangul Jamo Extended-B
}

func isHangul(r rune) bool {
	for _, b := range hangulBlocks {
		if r >= b[0] && r <= b[1] {
			return true
		}
	}
	return false
}

// koreanPages returns every generated page under site/ko.
func koreanPages(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(repoRoot(t), "site", "ko")
	var pages []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".html") {
			pages = append(pages, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) < 10 {
		t.Fatalf("found %d Korean pages under site/ko; the walk is broken, and a broken "+
			"walk makes every test below pass vacuously", len(pages))
	}
	return pages
}

func TestEveryKoreanSyllableOnTheSiteHasAGlyph(t *testing.T) {
	m := readKoreanManifest(t)

	// The whole file, not just its text nodes: an aria-label is read aloud and
	// a title attribute is shown in a tooltip, so a syllable there needs a
	// glyph as much as one in a paragraph does.
	missing := map[rune][]string{}
	for _, page := range koreanPages(t) {
		raw, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(repoRoot(t), page)
		for _, r := range string(raw) {
			if !isHangul(r) || m.syllables[r] {
				continue
			}
			if !contains(missing[r], rel) {
				missing[r] = append(missing[r], rel)
			}
		}
	}

	if len(missing) == 0 {
		return
	}
	var runes []rune
	for r := range missing {
		runes = append(runes, r)
	}
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })

	var b strings.Builder
	for _, r := range runes {
		fmt.Fprintf(&b, "\n    %q (U+%04X) in %s", r, r, strings.Join(missing[r], ", "))
	}
	t.Errorf("%d Hangul codepoint(s) on the Korean site have no glyph in the shipped subset:%s\n\n"+
		"  Each of these renders in the reader's system font, alone, in the middle of a\n"+
		"  word — a different face at a size nobody chose, with correct characters on\n"+
		"  either side of it.\n\n"+
		"  Rebuild the fonts:  pip install fonttools brotli && python3 scripts/korean-subset.py\n"+
		"  and commit site/assets/fonts/ along with the Korean copy that needed them.",
		len(missing), b.String())
}

func TestTheKoreanFontsAreTheOnesTheManifestDescribes(t *testing.T) {
	m := readKoreanManifest(t)
	dir := filepath.Join(repoRoot(t), "site", "assets", "fonts")

	for _, f := range m.fonts {
		blob, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			t.Errorf("%s is named by %s but is not there: %v", f.name, koreanManifestPath, err)
			continue
		}
		sum := sha256.Sum256(blob)
		if got := hex.EncodeToString(sum[:]); got != f.sha256 {
			t.Errorf("site/assets/fonts/%s does not hash to what %s recorded.\n"+
				"    manifest sha256 %s (%d bytes)\n"+
				"    file     sha256 %s (%d bytes)\n"+
				"  The font and the record of what it covers came from different runs, so the\n"+
				"  coverage test above is checking the wrong thing. Re-run scripts/korean-subset.py.",
				f.name, koreanManifestPath, f.sha256, f.size, got, len(blob))
		}
	}

	// Every face the stylesheet asks for has to be one of them: a @font-face
	// pointing at a file the manifest never described is a face whose coverage
	// nothing checks, and it 404s if the file is missing entirely.
	css := readSiteCSS(t, "korean.css")
	for _, ref := range regexp.MustCompile(`url\(assets/fonts/([^)]+)\)`).FindAllStringSubmatch(css, -1) {
		var known bool
		for _, f := range m.fonts {
			known = known || f.name == ref[1]
		}
		if !known {
			t.Errorf("site/korean.css loads assets/fonts/%s, which %s does not describe",
				ref[1], koreanManifestPath)
		}
	}
}

func readSiteCSS(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "site", name))
	if err != nil {
		t.Fatalf("site/%s: %v", name, err)
	}
	return string(raw)
}

// stripCSSComments removes /* … */ so a brace or a selector inside prose is
// not read as part of a rule. Both stylesheets carry long explanatory ones.
var cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

func stripCSSComments(s string) string { return cssComment.ReplaceAllString(s, "") }

// trackedSelector is one selector that opens a rule setting letter-spacing.
type trackedSelector struct {
	file     string
	selector string
	value    float64
}

// wideTrackedSelectors finds every rule in a stylesheet that opens up a
// label's letter-spacing, and returns the individual selectors that carry it.
//
// The walk back from the declaration stops at the nearest `{` *or* `}`, which
// is what keeps a rule nested inside an @media block from picking the media
// query up as part of its selector.
func wideTrackedSelectors(t *testing.T, file string, min float64) []trackedSelector {
	t.Helper()
	css := stripCSSComments(readSiteCSS(t, file))
	decl := regexp.MustCompile(`letter-spacing:\s*([0-9.]+)em`)

	var found []trackedSelector
	for _, loc := range decl.FindAllStringSubmatchIndex(css, -1) {
		value, err := strconv.ParseFloat(css[loc[2]:loc[3]], 64)
		if err != nil || value <= min {
			continue
		}
		open := strings.LastIndex(css[:loc[0]], "{")
		if open < 0 {
			continue
		}
		start := strings.LastIndexAny(css[:open], "{}") + 1
		for _, sel := range strings.Split(css[start:open], ",") {
			if sel = strings.Join(strings.Fields(sel), " "); sel != "" {
				found = append(found, trackedSelector{file: file, selector: sel, value: value})
			}
		}
	}
	return found
}

// Tracking is the measurement that transfers worst between the two scripts.
// The Latin design letterspaces its uppercase micro-labels — 0.14em on the
// eyebrow, 0.11em on the kickers — because capitals set tight without it.
// Hangul is square and carries its own sidebearings, so the same numbers push
// a Korean label apart into loose syllables, and the eyebrow on the Korean
// landing page is a full sentence of them.
//
// site/korean.css answers with one value for all of them rather than a Korean
// counterpart per Latin number, so there is nothing to keep numerically in
// step. What there *is* to keep in step is the list of selectors, and a new
// label added to either stylesheet would join it silently. Hence this.
func TestKoreanTypographyRetracksEveryWideLabel(t *testing.T) {
	const threshold = 0.05

	// .hero-panel::before's text is a CSS string — "SCAN SHEET" — so it is
	// Latin on the Korean pages too, and retracking it would only loosen the
	// one label on the page that is not translated.
	exempt := map[string]string{
		".hero-panel::before": "its content is a CSS string, Latin in both languages",
	}

	korean := stripCSSComments(readSiteCSS(t, "korean.css"))
	var wide []trackedSelector
	wide = append(wide, wideTrackedSelectors(t, "styles.css", threshold)...)
	wide = append(wide, wideTrackedSelectors(t, "docs.css", threshold)...)
	if len(wide) < 5 {
		t.Fatalf("harvested only %d wide-tracked selectors from the stylesheets; the parse "+
			"is broken, and a broken parse makes this test pass on anything", len(wide))
	}

	for _, w := range wide {
		if _, ok := exempt[w.selector]; ok {
			continue
		}
		if strings.Contains(korean, w.selector) {
			continue
		}
		t.Errorf("site/%s tracks %s at %gem, and site/korean.css does not retrack it.\n"+
			"  At that width Hangul sets as separated syllables rather than as a word. Add\n"+
			"  the selector to the --track-ko-label rule in site/korean.css, or exempt it\n"+
			"  here with the reason its text is never Korean.", w.file, w.selector, w.value)
	}
}

// The English pages carry exactly three Hangul syllables — 한국어, the language
// switcher — and linking korean.css from them would have every English reader
// fetch a 112KB Korean serif to draw them. The Korean pages, conversely, are
// unreadable-as-designed without it: they fall back to whatever the reader's
// system has, which is the problem the file exists to solve.
func TestOnlyTheKoreanPagesLinkTheKoreanStylesheet(t *testing.T) {
	root := filepath.Join(repoRoot(t), "site")
	koDir := filepath.Join(root, "ko") + string(filepath.Separator)

	var seen int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		seen++
		rel, _ := filepath.Rel(repoRoot(t), path)
		links := strings.Contains(string(raw), "korean.css")
		switch korean := strings.HasPrefix(path, koDir); {
		case korean && !links:
			t.Errorf("%s is a Korean page and does not link korean.css, so its Hangul is "+
				"drawn by whatever the reader's system falls back to", rel)
		case !korean && links:
			t.Errorf("%s is an English page and links korean.css, which makes every English "+
				"reader fetch a Korean serif for the three syllables in the 한국어 switcher", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 20 {
		t.Fatalf("walked only %d pages under site/; the walk is broken", seen)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
