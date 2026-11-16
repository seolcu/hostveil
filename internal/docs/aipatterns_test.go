package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// The writing rules in AGENTS.md ("Writing rules") cover every file in the
// repository. This test holds the mechanical part of them: the em dash, the
// "rather than" and "not just" contrasts, and the words that mark text as
// machine-written. The rest (metaphor, sentence headings, triads, a bare
// "A, not B") needs a reader, so AGENTS.md is where those live.
//
// AGENTS.md itself is exempt because it names the patterns, and so is this
// file. Generated output (site/), committed measurement records, fixtures
// under testdata/ and third-party texts (LICENSE, CODE_OF_CONDUCT.md) are
// not ours to rewrite.

var aiPatternRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"contrast \"rather than\"", regexp.MustCompile(`(?i)\brather than\b`)},
	{"contrast \"not just/only/merely\"", regexp.MustCompile(`(?i)\bnot (just|only|merely)\b`)},
	{"contrast \"A가/이 아니라 B\"", regexp.MustCompile(`[가-힣](이|가) 아니라 `)},
	{"model word", regexp.MustCompile(`(?i)\b(deliberately|on purpose|genuinely|plainly|honestly|honest|quietly|outright|load-bearing|worth noting|the whole point|seamless(ly)?|delve|tapestry|testament)\b`)},
	{"model word (Korean)", regexp.MustCompile(`일부러|정직하게|조용히|결론적으로|종합하면`)},
}

var aiPatternSkipDirs = map[string]bool{
	"site": true, "testdata": true, "reports": true, "node_modules": true,
}

var aiPatternSkipFiles = map[string]bool{
	"AGENTS.md":                        true,
	"LICENSE":                          true,
	"CODE_OF_CONDUCT.md":               true,
	"internal/docs/aipatterns_test.go": true,
}

var aiPatternSkipPrefixes = []string{
	"docs/measurements/",
	"scripts/forensics/measurements/",
	"scripts/forensics/results/", // gitignored experiment output
}

var aiPatternExts = map[string]bool{
	".go": true, ".md": true, ".html": true, ".tmpl": true, ".js": true, ".css": true,
	".sh": true, ".py": true, ".yml": true, ".yaml": true, ".cff": true, ".example": true,
}

func TestNoAIWritingPatterns(t *testing.T) {
	root := repoRoot(t)
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			name := d.Name()
			if path != root && (aiPatternSkipDirs[name] || (strings.HasPrefix(name, ".") && name != ".github")) {
				return filepath.SkipDir
			}
			return nil
		}
		if aiPatternSkipFiles[rel] || !aiPatternWanted(d.Name()) {
			return nil
		}
		for _, p := range aiPatternSkipPrefixes {
			if strings.HasPrefix(rel, p) {
				return nil
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for n, line := range strings.Split(string(b), "\n") {
			for _, r := range aiPatternRules {
				if m := r.re.FindString(line); m != "" {
					t.Errorf("%s:%d: %s %q (see \"Writing rules\" in AGENTS.md)", rel, n+1, r.name, m)
				}
			}
			if col := emDashBetweenWords(line); col >= 0 {
				t.Errorf("%s:%d: em dash between words (see \"Writing rules\" in AGENTS.md)", rel, n+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 300 {
		t.Fatalf("only %d files checked; the walk is broken", checked)
	}
}

func aiPatternWanted(name string) bool {
	if name == "Vagrantfile" || name == "Dockerfile" {
		return true
	}
	return aiPatternExts[filepath.Ext(name)]
}

// emDashBetweenWords returns the byte offset of the first em dash (or
// &mdash;) that joins two pieces of prose, or -1. A dash standing alone, such
// as a table cell meaning "none" or a quoted "—" value, has no word on one
// side and is allowed.
func emDashBetweenWords(line string) int {
	for _, dash := range []string{"—", "&mdash;"} {
		from := 0
		for {
			i := strings.Index(line[from:], dash)
			if i < 0 {
				break
			}
			i += from
			left := strings.TrimRight(line[:i], " \t")
			right := strings.TrimLeft(line[i+len(dash):], " \t")
			if left != "" && right != "" {
				l, _ := lastRune(left)
				r := []rune(right)[0]
				if wordish(l) && (wordish(r) || r == '(') {
					return i
				}
			}
			from = i + len(dash)
		}
	}
	return -1
}

func lastRune(s string) (rune, bool) {
	r := []rune(s)
	if len(r) == 0 {
		return 0, false
	}
	return r[len(r)-1], true
}

func wordish(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(").`*", r)
}
