package docs

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// measurements.html is not the only page that publishes the run.
//
// Every figure on that page carries data-measured and is checked against the
// committed JSON, and that guard has been extended twice — once for three
// claims nobody was checking, once for an architecture no run recorded. Both
// times the fix covered measurements.html and nothing else, because that is
// the file the test reads.
//
// Meanwhile the landing page leads with the same four numbers, and both
// READMEs carry the same table and a paragraph of prose around it. Those had
// no guard at all, and by 3.20.0 they had drifted exactly the way the page
// would have: the READMEs quoted the *previous* run's rollback tally beside
// the current run's table, and the ARM64 claim that #731 removed from the page
// was still standing in all four files.
//
// So this is the same pin, applied to every file that quotes a run.
func runQuotingPages() []string {
	return []string{
		filepath.Join("cmd", "sitegen", "content", "en", "docs", "measurements.html"),
		filepath.Join("cmd", "sitegen", "content", "ko", "docs", "measurements.html"),
		filepath.Join("cmd", "sitegen", "content", "en", "index.html"),
		filepath.Join("cmd", "sitegen", "content", "ko", "index.html"),
		"README.md",
		"README.ko.md",
	}
}

// TestNoPublishedPageNamesAnArchitectureTheRunDidNotRecord is
// TestThePageOnlyNamesAnArchitectureTheRunRecorded's rule over the whole set.
//
// The narrower test passed on 3.20.0 while README.md:284 said "a real ARM64
// server", README.ko.md said the same, and both landing pages said it in the
// caption under the figures. #731 established that no committed run carries
// host.arch and removed the claim from the page it was reading; the claim went
// on being published in four other files and one generated copy of each.
func TestNoPublishedPageNamesAnArchitectureTheRunDidNotRecord(t *testing.T) {
	name, doc := newestMeasurement(t)
	recorded := ""
	if v, err := resolveJSON(doc, "host.arch"); err == nil {
		recorded = strings.ToLower(renderJSON(v))
	}

	for _, page := range runQuotingPages() {
		for _, m := range archWords.FindAllString(proseOnly(readRepoFile(t, page)), -1) {
			word := strings.ToLower(m)
			switch {
			case recorded == "":
				t.Errorf("%s says %q and %s records no host.arch at all — either the run has to "+
					"carry it or the page must not name one", page, m, name)
			case !sameArch(word, recorded):
				t.Errorf("%s says %q and %s recorded %q", page, m, name, recorded)
			}
		}
	}
}

// TestEveryFigureOnTheLandingPageCameOffTheCommittedRun is
// TestEveryPublishedFigureCameOffTheCommittedRun over the other HTML pages
// that quote the run.
//
// The landing page leads with the four figures the whole site is arguing
// from — ports answering, CIS checks passing, the Lynis index, the score —
// and carried them as bare text. They happened to match the newest run, and
// nothing would have said so if they stopped: the next committed run would
// have failed the docs page, been corrected there, and left the front page
// quoting the run before it. They carry data-measured now, and this reads it.
func TestEveryFigureOnTheLandingPageCameOffTheCommittedRun(t *testing.T) {
	name, doc := newestMeasurement(t)

	for _, page := range []string{
		filepath.Join("cmd", "sitegen", "content", "en", "index.html"),
		filepath.Join("cmd", "sitegen", "content", "ko", "index.html"),
	} {
		cells := measuredCell.FindAllStringSubmatch(readRepoFile(t, page), -1)
		if len(cells) == 0 {
			t.Errorf("%s cites no figure at all — the measured section publishes numbers, "+
				"and a number with no data-measured is a number nothing checks", page)
			continue
		}
		for _, c := range cells {
			path, shown := c[1], strings.TrimSpace(c[2])
			want, err := resolveJSON(doc, path)
			if err != nil {
				t.Errorf("%s: data-measured=%q does not resolve in %s: %v", page, path, name, err)
				continue
			}
			if got := renderJSON(want); got != shown {
				t.Errorf("%s says %q for %s, and %s records %q", page, shown, path, name, got)
			}
		}
	}
}

// proseClaim is one sentence a published page makes about the run, in the
// words that page uses, with the figures filled in from the committed JSON.
//
// A data-measured cell works where the number stands alone in a tag. It does
// not reach a Markdown README, and it does not reach a sentence that spells the
// figure as a word — which is what the site's own section heading does. So the
// unit here is the phrase: build it from the run, require it verbatim. That is stricter than
// checking the digits alone — it fails a README that quotes a right number in
// a sentence that has stopped being true around it — and it is what caught
// the case this test was written for, where the table above the paragraph came
// off the newest run and the paragraph below it came off the previous one.
type proseClaim struct {
	file  string
	what  string
	parts []string // JSON paths, substituted into phrase in order
	// phrase is the required text with %s where each part goes, or %w where
	// the prose spells the figure as a word. Whitespace is normalised on both
	// sides before comparing, so a claim may wrap wherever it likes.
	phrase string
}

// spelledOut renders a figure the way the prose spells it.
//
// The English half inverts agents_test.go's numberWords rather than restating
// the same twenty words beside it — two tables of one vocabulary is two places
// for it to drift, which is the argument this whole file is making about
// figures. The Korean half has no existing table to borrow and covers only the
// range a port count lands in; a figure outside it fails loudly, because a
// headline naming a number nothing checks is the defect being closed here.
var koreanNumberWords = map[string]string{
	"0": "영", "1": "하나", "2": "둘", "3": "셋", "4": "넷",
	"5": "다섯", "6": "여섯", "7": "일곱", "8": "여덟", "9": "아홉", "10": "열",
}

func spelledOut(digits string, korean bool) (string, bool) {
	if korean {
		w, ok := koreanNumberWords[digits]
		return w, ok
	}
	for word, n := range numberWords {
		if strconv.Itoa(n) == digits {
			return word, true
		}
	}
	return "", false
}

func publishedProseClaims() []proseClaim {
	return []proseClaim{
		// The loudest measured claim on the site is its section heading, and
		// it was the one carrying no pin at all — spelled out in words, where
		// even a search for the digits would not have found it.
		{
			file:   filepath.Join("cmd", "sitegen", "content", "en", "index.html"),
			what:   "the headline count of ports answering from off the host",
			parts:  []string{"phases.before.external_scan.count", "phases.reviewed.external_scan.count"},
			phrase: "%w ports answered from off the host. Then %w.",
		},
		{
			file:   filepath.Join("cmd", "sitegen", "content", "ko", "index.html"),
			what:   "the headline count of ports answering from off the host",
			parts:  []string{"phases.before.external_scan.count", "phases.reviewed.external_scan.count"},
			phrase: "호스트 밖에서 응답하던 포트 %w 개, 그다음엔 %w.",
		},
		{
			file:   "README.md",
			what:   "the rollback tally",
			parts:  []string{"rollback.paths_restored_exactly", "rollback.paths_changed_by_fixes", "rollback.checkpoints_rolled_back"},
			phrase: "%s of %s, across %s checkpoints",
		},
		{
			file:   "README.md",
			what:   "how many reviewed fixes left nothing to roll back",
			parts:  []string{"reviewed.not_reversible", "reviewed.applied"},
			phrase: "%s of the %s reviewed fixes leave nothing to roll back",
		},
		{
			file:   "README.md",
			what:   "how many warnings Lynis raised",
			parts:  []string{"phases.reviewed.lynis.warnings"},
			phrase: "Two of Lynis's %s warnings",
		},
		{
			file:   "README.ko.md",
			what:   "the rollback tally",
			parts:  []string{"rollback.checkpoints_rolled_back", "rollback.paths_restored_exactly", "rollback.paths_changed_by_fixes"},
			phrase: "체크포인트 %s개에 걸쳐 %s개 중 %s개입니다",
		},
		{
			file:   "README.ko.md",
			what:   "how many reviewed fixes left nothing to roll back",
			parts:  []string{"reviewed.applied", "reviewed.not_reversible"},
			phrase: "Review 수정 %s건 중 %s건은 되돌릴 것이 애초에 없습니다",
		},
		{
			file:   "README.ko.md",
			what:   "how many warnings Lynis raised",
			parts:  []string{"phases.reviewed.lynis.warnings"},
			phrase: "Lynis 경고 %s건 중 2건은",
		},
	}
}

func TestEveryProseFigureQuotesTheNewestRunAndNotAnOlderOne(t *testing.T) {
	name, doc := newestMeasurement(t)

	for _, c := range publishedProseClaims() {
		want := c.phrase
		ok := true
		korean := strings.Contains(c.file, string(filepath.Separator)+"ko"+string(filepath.Separator)) ||
			strings.HasSuffix(c.file, ".ko.md")
		for _, p := range c.parts {
			v, err := resolveJSON(doc, p)
			if err != nil {
				t.Errorf("%s: %s cites %s, which does not resolve in %s: %v", c.file, c.what, p, name, err)
				ok = false
				break
			}
			digits := renderJSON(v)
			// %w before %s when the phrase reaches one first, so a claim may
			// mix a spelled figure and a numeral.
			wi, si := strings.Index(want, "%w"), strings.Index(want, "%s")
			if wi >= 0 && (si < 0 || wi < si) {
				word, known := spelledOut(digits, korean)
				if !known {
					t.Errorf("%s: %s resolves to %q and this test has no word for it — extend "+
						"koreanNumberWords or numberWords, rather than letting the headline go "+
						"back to being a sentence nothing reads", c.file, p, digits)
					ok = false
					break
				}
				want = strings.Replace(want, "%w", word, 1)
				continue
			}
			want = strings.Replace(want, "%s", digits, 1)
		}
		if !ok {
			continue
		}
		// Case-folded, because prose capitalises at the start of a sentence
		// and the claim being pinned is the figure, not the capital.
		if !strings.Contains(strings.ToLower(squash(readRepoFile(t, c.file))), strings.ToLower(squash(want))) {
			t.Errorf("%s does not state %s the way %s records it.\n"+
				"  expected to find: %q\n"+
				"  The table above that paragraph is pinned and the paragraph was not, which is how "+
				"one run's figures came to sit beside another run's prose.", c.file, c.what, name, want)
		}
	}
}

// squash collapses every run of whitespace to one space, so a claim may be
// wrapped across lines — which both READMEs do, and the Korean one does in the
// middle of the sentences pinned above.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// proseOnly removes code from a Markdown or HTML document, because prose and
// code say an architecture for different reasons.
//
// "a real ARM64 server" is a claim about the host that was measured, and it
// has to be true. `hostveil_<version>_linux_amd64.deb` is the name of a file
// on the releases page, which is true regardless of what the harness ran on
// and would still be true if no measurement existed at all. Scanning both
// would make the install instructions fail a test about the measurement, and
// the only way to pass it would be to stop naming the packages hostveil
// actually publishes.
var codeSpans = regexp.MustCompile("(?s)```.*?```|`[^`\n]*`|<code[^>]*>.*?</code>|<pre[^>]*>.*?</pre>")

// proseOnly reduces a page to the words a reader actually sees.
//
// Code spans go first, because a command or a path may legitimately name an
// architecture. Then the tags themselves, keeping their inner text and
// dropping their attributes: an attribute is markup, never rendered, and the
// rule this feeds is about a page *telling* someone the host was arm64.
//
// The attribute half was added when a run was cited by filename —
// data-measured-run="…-arm64-….json" — and the guard read the citation as the
// claim. That is a reference to a committed file, resolved by
// TestEveryPublishedFigureCameOffTheCommittedRun against the run it names; the
// reader sees the figure, not the filename. Stripping tags leaves the guard
// exactly as strong over everything that reaches a screen.
func proseOnly(doc string) string {
	return htmlTags.ReplaceAllString(codeSpans.ReplaceAllString(doc, " "), " ")
}

var htmlTags = regexp.MustCompile(`<[^<>]*>`)
