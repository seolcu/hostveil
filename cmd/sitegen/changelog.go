package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// The changelog page is generated from CHANGELOG.md and CHANGELOG.ko.md rather
// than hand-written into content/, because a hand-written copy would be the
// third place the same prose lives and the second place it can go stale.
//
// That is not a hypothetical here. #736 landed one release before this page
// existed, and it was exactly this: the landing page and both READMEs quoted
// figures that had drifted from the run they came off, because they were
// copies with nothing holding them to the original. A changelog page typed out
// by hand would be the same shape of mistake, one release later, about the
// document whose whole job is to say what changed.
//
// So the source files are read at generation time. sitegen already resolves
// its output directory against the working directory; these are read the same
// way, which is why `go run ./cmd/sitegen` is documented as being run from the
// repository root.

// changelogFile is the source for one language's page.
func changelogFile(lang string) string {
	if lang == "ko" {
		return "CHANGELOG.ko.md"
	}
	return "CHANGELOG.md"
}

// renderChangelog reads a changelog and returns the HTML for its release
// entries — everything from the first version heading on.
//
// What comes before that heading is the file's own front matter: an H1 the
// page already has in its own title, and a link to the other language that the
// site's language switcher already provides. The page's introduction lives in
// content/{en,ko}/docs/changelog.html with every other page's, because it is
// site chrome and not changelog data.
func renderChangelog(lang string) (string, error) {
	raw, err := os.ReadFile(changelogFile(lang))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", changelogFile(lang), err)
	}
	body := string(raw)
	if i := strings.Index(body, "\n## "); i >= 0 {
		body = body[i+1:]
	}
	if err := checkChangelogSyntax(changelogFile(lang), body); err != nil {
		return "", err
	}
	return changelogHTML(body), nil
}

var (
	// versionHeading matches "## [3.20.1](compare-url) (2026-08-15)".
	versionHeading = regexp.MustCompile(`^## \[([^\]]+)\]\(([^)]+)\)(?:\s+\((.+)\))?\s*$`)
	// mdLink, mdCode, mdBold and mdEm are the whole inline vocabulary the
	// changelog uses. Underscores are deliberately absent: every one in the
	// file is inside a code span (`sshd_config`, `HOSTVEIL_DEBUG`), and
	// treating them as emphasis would eat identifiers.
	mdLink = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	mdBold = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdEm   = regexp.MustCompile(`\*([^*]+)\*`)
)

// unsupported are the Markdown constructs this converter does not implement.
//
// They are an error rather than a silent passthrough. A minimal converter is
// the right trade for a file whose syntax this project controls — it keeps a
// Markdown dependency out of a six-dependency module for the sake of one page
// — but only if it says so when the file outgrows it. Rendering a table as a
// row of pipes, or a fenced block as literal backticks, would publish a
// mangled changelog and nothing would notice.
var unsupported = []struct {
	pattern *regexp.Regexp
	what    string
}{
	{regexp.MustCompile("(?m)^```"), "a fenced code block"},
	{regexp.MustCompile(`(?m)^\s*\|`), "a table"},
	{regexp.MustCompile(`(?m)^\s*> `), "a blockquote"},
	{regexp.MustCompile(`!\[`), "an image"},
	{regexp.MustCompile(`(?m)^\s*\d+\. `), "an ordered list"},
	{regexp.MustCompile(`(?m)^  [*-] `), "a nested list"},
	{regexp.MustCompile("(?m)^    [^ ]"), "an indented code block"},
}

func checkChangelogSyntax(name, body string) error {
	for _, u := range unsupported {
		if loc := u.pattern.FindStringIndex(body); loc != nil {
			line := strings.Count(body[:loc[0]], "\n") + 1
			return fmt.Errorf("%s:%d uses %s, which cmd/sitegen/changelog.go does not render.\n"+
				"Either write the entry in the subset the rest of the file uses — headings, "+
				"bullets, links, `code`, **bold**, *emphasis* — or teach changelogHTML to render it. "+
				"Publishing it unrendered is the one option that is not available",
				name, line, u.what)
		}
	}
	return nil
}

// changelogHTML converts the release-entry portion of a changelog.
//
// The block grammar is the whole of what the file uses: version headings,
// section headings, and flat bullets whose continuation lines are indented two
// spaces and whose paragraphs are separated by blank lines.
func changelogHTML(body string) string {
	var b strings.Builder
	var item []string // the current bullet's raw lines, continuations joined
	var para []string // a top-level paragraph, which the file wraps at 76 columns

	flushPara := func() {
		if len(para) == 0 {
			return
		}
		fmt.Fprintf(&b, "          <p>%s</p>\n", inline(strings.Join(para, " ")))
		para = nil
	}

	flushItem := func() {
		if len(item) == 0 {
			return
		}
		b.WriteString("            <li>\n")
		for _, para := range splitParagraphs(item) {
			fmt.Fprintf(&b, "              <p>%s</p>\n", inline(para))
		}
		b.WriteString("            </li>\n")
		item = nil
	}
	inList := false
	closeList := func() {
		flushItem()
		if inList {
			b.WriteString("          </ul>\n")
			inList = false
		}
	}
	endBlock := func() {
		flushPara()
		closeList()
	}

	for _, line := range strings.Split(body, "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			endBlock()
			b.WriteString(versionHTML(line))
		case strings.HasPrefix(line, "### "):
			endBlock()
			fmt.Fprintf(&b, "          <h3>%s</h3>\n", inline(strings.TrimSpace(line[4:])))
		case strings.HasPrefix(line, "* "):
			flushPara()
			flushItem()
			if !inList {
				b.WriteString("          <ul class=\"changelog-entries\">\n")
				inList = true
			}
			item = []string{strings.TrimSpace(line[2:])}
		case strings.HasPrefix(line, "  ") && len(item) > 0:
			item = append(item, strings.TrimSpace(line))
		case strings.TrimSpace(line) == "":
			// A blank line ends a top-level paragraph, and inside a bullet it
			// separates two of them rather than ending the bullet — the entry
			// continues on the next indented line.
			flushPara()
			if len(item) > 0 {
				item = append(item, "")
			}
		default:
			// A top-level paragraph: the sentence or two under a version
			// heading saying what the release is about. It arrives one wrapped
			// line at a time and is joined back up, or every line of it
			// becomes a paragraph of its own.
			closeList()
			para = append(para, strings.TrimSpace(line))
		}
	}
	endBlock()
	return strings.TrimRight(b.String(), "\n")
}

// splitParagraphs joins a bullet's wrapped lines back into paragraphs. The
// file wraps at 76 columns, so a paragraph arrives as several lines and a
// blank entry marks the break between two.
func splitParagraphs(lines []string) []string {
	var out []string
	var cur []string
	for _, l := range lines {
		if l == "" {
			if len(cur) > 0 {
				out = append(out, strings.Join(cur, " "))
				cur = nil
			}
			continue
		}
		cur = append(cur, l)
	}
	if len(cur) > 0 {
		out = append(out, strings.Join(cur, " "))
	}
	return out
}

// versionHTML renders a version heading, with an id so a release can be linked
// to directly — which is the thing a changelog page is for that a file in the
// repository is not.
func versionHTML(line string) string {
	m := versionHeading.FindStringSubmatch(line)
	if m == nil {
		// Not the shape this file has used for thirty-one releases; render the
		// text rather than dropping the heading on the floor.
		return fmt.Sprintf("          <h2>%s</h2>\n", inline(strings.TrimSpace(line[3:])))
	}
	version, compareURL, date := m[1], m[2], m[3]
	var b strings.Builder
	fmt.Fprintf(&b, "          <h2 id=\"v%s\"><a href=\"%s\">%s</a>",
		escAttr(version), escAttr(compareURL), escText(version))
	if date != "" {
		fmt.Fprintf(&b, " <span class=\"changelog-date\">%s</span>", escText(date))
	}
	b.WriteString("</h2>\n")
	return b.String()
}

// inline renders the four inline constructs, escaping first so that anything
// the changelog quotes — `/etc/systemd/system/<unit>.d/`, `.chip.c-<abbr>` —
// reaches the page as text rather than as a tag.
func inline(s string) string {
	s = escText(s)
	// Code first, and its content is left alone afterwards: a path or a
	// selector inside backticks must not have its asterisks read as emphasis.
	var codes []string
	s = replaceCode(s, func(inner string) string {
		codes = append(codes, inner)
		return fmt.Sprintf("\x00%d\x00", len(codes)-1)
	})
	s = mdLink.ReplaceAllString(s, `<a href="$2">$1</a>`)
	s = mdBold.ReplaceAllString(s, "<strong>$1</strong>")
	s = mdEm.ReplaceAllString(s, "<em>$1</em>")
	for i, c := range codes {
		s = strings.Replace(s, fmt.Sprintf("\x00%d\x00", i), "<code>"+c+"</code>", 1)
	}
	return s
}

// replaceCode walks backtick spans by hand rather than by regexp, because the
// changelog contains backticks inside prose about backticks and a greedy or
// lazy pattern gets one of those two cases wrong.
func replaceCode(s string, fn func(string) string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "`")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.Index(s[i+1:], "`")
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(fn(s[i+1 : i+1+j]))
		s = s[i+j+2:]
	}
}
