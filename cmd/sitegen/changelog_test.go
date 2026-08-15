package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRootFromSitegen walks up to the module root, because these tests read
// CHANGELOG.md the way sitegen does — from the working directory — and `go
// test` runs each package in its own directory.
func repoRootFromSitegen(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root from the sitegen package")
	return ""
}

func inRepoRoot(t *testing.T) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoRootFromSitegen(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
}

// TestEveryReleaseReachesTheChangelogPage is the pin that makes generating the
// page worth more than writing it.
//
// A hand-written page can omit a release and look complete. This one is
// converted from the file, so the only way it can omit one is a converter bug
// — which is what this catches, by requiring every version heading in the
// source to arrive as a linkable heading in the output.
func TestEveryReleaseReachesTheChangelogPage(t *testing.T) {
	inRepoRoot(t)

	for _, lang := range []string{"en", "ko"} {
		src, err := os.ReadFile(changelogFile(lang))
		if err != nil {
			t.Fatal(err)
		}
		want := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindAllStringSubmatch(string(src), -1)
		if len(want) == 0 {
			t.Fatalf("%s has no version headings at all", changelogFile(lang))
		}

		got, err := renderChangelog(lang)
		if err != nil {
			t.Fatalf("%s: %v", lang, err)
		}
		for _, m := range want {
			anchor := `<h2 id="v` + m[1] + `">`
			if !strings.Contains(got, anchor) {
				t.Errorf("%s: release %s is in %s and not on the page (no %s)",
					lang, m[1], changelogFile(lang), anchor)
			}
		}
		if n := strings.Count(got, `<h2 id="v`); n != len(want) {
			t.Errorf("%s: %d version headings in the source and %d on the page", lang, len(want), n)
		}
	}
}

// TestTheChangelogPageEscapesWhatItQuotes.
//
// The changelog quotes paths and CSS selectors that contain angle brackets —
// `/etc/systemd/system/<unit>.d/`, `.chip.c-<abbr>` — and a converter that
// passed those through would put a tag on the page where the file has text.
// They are inside code spans, which is exactly where a naive converter is most
// likely to stop escaping.
func TestTheChangelogPageEscapesWhatItQuotes(t *testing.T) {
	got := changelogHTML("* **core:** a path like `/etc/systemd/system/<unit>.d/` and a <bare> one\n")
	if strings.Contains(got, "<unit>") || strings.Contains(got, "<bare>") {
		t.Errorf("an angle bracket reached the page as markup:\n%s", got)
	}
	for _, want := range []string{"&lt;unit&gt;", "&lt;bare&gt;", "<strong>core:</strong>"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestChangelogInlineConversion(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"code", "run `hostveil scan`", "run <code>hostveil scan</code>"},
		{"bold", "**core:** it moved", "<strong>core:</strong> it moved"},
		{"emphasis", "the *whole* point", "the <em>whole</em> point"},
		{"link", "see [#735](https://example.test/735)", `see <a href="https://example.test/735">#735</a>`},
		// The one that matters: emphasis must not be found inside a code span,
		// or a glob in a finding id becomes an <em>.
		{"asterisk in code", "the `systemd.*` glob and `compose.*` too",
			"the <code>systemd.*</code> glob and <code>compose.*</code> too"},
		// Underscores are identifiers here, never emphasis.
		{"underscores", "`sshd_config` and `HOSTVEIL_DEBUG`",
			"<code>sshd_config</code> and <code>HOSTVEIL_DEBUG</code>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := inline(tc.in); got != tc.want {
				t.Errorf("inline(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestUnsupportedMarkdownFailsTheBuild.
//
// The converter implements the subset the changelog uses, which is the right
// trade only while it says so out loud when the file outgrows it. A table
// rendered as a row of pipes would publish a mangled release and nothing would
// notice, so sitegen refuses to write the page instead.
func TestUnsupportedMarkdownFailsTheBuild(t *testing.T) {
	for name, body := range map[string]string{
		"a table":           "## [1.0.0](u) (d)\n\n| a | b |\n| - | - |\n",
		"a fenced block":    "## [1.0.0](u) (d)\n\n```go\nx := 1\n```\n",
		"a blockquote":      "## [1.0.0](u) (d)\n\n> quoted\n",
		"an image":          "## [1.0.0](u) (d)\n\n![alt](x.png)\n",
		"an ordered list":   "## [1.0.0](u) (d)\n\n1. first\n",
		"a nested list":     "## [1.0.0](u) (d)\n\n* top\n  * nested\n",
		"an indented block": "## [1.0.0](u) (d)\n\n    code\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := checkChangelogSyntax("CHANGELOG.md", body)
			if err == nil {
				t.Fatalf("%s was accepted; it would have been published unrendered", name)
			}
			if !strings.Contains(err.Error(), "CHANGELOG.md:") {
				t.Errorf("the error does not say where to look: %v", err)
			}
		})
	}

	// And the shapes the file actually uses must keep passing, or the guard
	// has stopped being a guard and started being a wall.
	ok := "## [3.20.1](https://x/compare) (2026-08-15)\n\nAn intro line.\n\n### Bug Fixes\n\n" +
		"* **core:** it moved ([#735](https://x/735)). With `code`, **bold** and *emphasis*.\n" +
		"  A second line of the same paragraph.\n\n  And a second paragraph.\n"
	if err := checkChangelogSyntax("CHANGELOG.md", ok); err != nil {
		t.Errorf("the subset the changelog is written in was rejected: %v", err)
	}
}

// TestTheChangelogPageIsGeneratedNotWritten guards the arrangement itself: the
// content fragment carries the page's introduction and a marker, and the
// releases are injected there. A fragment that lost the marker would render a
// changelog page with no changelog on it, and every other test here would still
// pass because they exercise the converter rather than the page.
func TestTheChangelogPageIsGeneratedNotWritten(t *testing.T) {
	inRepoRoot(t)

	for _, lang := range []string{"en", "ko"} {
		raw, err := os.ReadFile(filepath.Join("cmd", "sitegen", "content", lang, "docs", changelogSlug+".html"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), changelogMarker) {
			t.Errorf("content/%s/docs/%s.html has no %s, so the releases have nowhere to go",
				lang, changelogSlug, changelogMarker)
		}
		if strings.Contains(string(raw), "<h2 id=\"v") {
			t.Errorf("content/%s/docs/%s.html writes a release out by hand; they come from %s",
				lang, changelogSlug, changelogFile(lang))
		}
	}
}
