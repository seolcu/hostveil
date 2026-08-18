package docs

import (
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// The two READMEs are one document in two languages, and nothing held them to
// the same shape.
//
// TestReadmeLocalReferencesExist checks that every link in each resolves;
// TestBothChangelogsCoverTheSameReleases does this job for the changelogs.
// Between the READMEs there was no structural pin at all — so a section could
// be added, moved or promoted in one and not the other, and the only way to
// notice would be to read both.
//
// That matters more after a reorder than before one. The English README's
// proof section spent every release as an H3 two thirds of the way down; the
// Korean one did too, because they were written together. Nothing was keeping
// them together.
var readmeSections = []struct{ en, ko string }{
	{"## Does it actually work?", "## 정말 효과가 있나요?"},
	{"## How it compares", "## 다른 도구와의 비교"},
	{"## What it checks", "## 점검 범위"},
	{"## How it's tested", "## 어떻게 테스트하나요?"},
	{"## Install", "## 설치"},
	{"## Usage", "## 사용법"},
	{"### Using it as a CI or cron gate", "### CI나 cron 게이트로 쓰기"},
	{"### When something looks wrong", "### 뭔가 이상해 보일 때"},
	{"## How fixing works", "## 수정은 어떻게 이뤄지나"},
	{"## How the score works", "## 점수는 어떻게 매겨지나"},
	{"## Interfaces", "## 인터페이스"},
	{"## AI (optional, advisory only)", "## AI (선택, 조언 전용)"},
	{"## Roadmap", "## 로드맵"},
	{"## Build from source", "## 소스에서 빌드하기"},
	{"## License", "## 라이선스"},
}

var mdHeading = regexp.MustCompile(`(?m)^#{2,3} .*$`)

func TestBothReadmesHaveTheSameSectionsInTheSameOrder(t *testing.T) {
	if len(readmeSections) < 10 {
		t.Fatalf("only %d section pairs are listed; the table is the only written-down copy "+
			"of this structure and a short one checks almost nothing", len(readmeSections))
	}

	for _, tc := range []struct {
		file string
		want func(int) string
	}{
		{"README.md", func(i int) string { return readmeSections[i].en }},
		{"README.ko.md", func(i int) string { return readmeSections[i].ko }},
	} {
		got := mdHeading.FindAllString(readRepoFile(t, tc.file), -1)
		for i := range got {
			got[i] = strings.TrimRight(got[i], " \t\r")
		}
		if len(got) != len(readmeSections) {
			t.Errorf("%s has %d headings and the table lists %d:\n  %s",
				tc.file, len(got), len(readmeSections), strings.Join(got, "\n  "))
			continue
		}
		for i := range readmeSections {
			if got[i] != tc.want(i) {
				t.Errorf("%s heading %d is %q, want %q — the two READMEs have to carry the same "+
					"sections in the same order, or one language quietly stops being the same document",
					tc.file, i+1, got[i], tc.want(i))
			}
		}
	}
}

// TestTheEnglishReadmeOpensInEnglish.
//
// Line 5 of README.md was `> 2026-1 Ajou SoftCon 개발부문 최우수상 수상` — the
// first content an English reader met, in a script most of them cannot read,
// above the sentence saying what hostveil is. CITATION.cff already carried the
// English rendering of exactly that line.
//
// Pinned narrowly rather than as a general language check: the language
// switcher on line 3 has to say 한국어, and quoted Korean further down (a
// finding title, a team name) is legitimate. What is not is Korean prose in
// the part a reader sees before deciding whether to keep reading.
func TestTheEnglishReadmeOpensInEnglish(t *testing.T) {
	body := readRepoFile(t, "README.md")
	head := body
	if i := strings.Index(body, "\n## "); i > 0 {
		head = body[:i]
	}
	for n, line := range strings.Split(head, "\n") {
		if strings.Contains(line, "README.ko.md") {
			continue // the language switcher, which has to name the language
		}
		for _, r := range line {
			if unicode.Is(unicode.Hangul, r) {
				t.Errorf("README.md:%d is Korean prose above the first section, where an English "+
					"reader decides whether to keep reading:\n  %s", n+1, strings.TrimSpace(line))
				break
			}
		}
	}
}
