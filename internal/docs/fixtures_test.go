package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The fixtures the interfaces are drawn from must name findings hostveil can
// actually report.
//
// findings_test.go closes the loop between the checkers and the docs: every ID
// a checker constructs has to be documented, and every documented row has to
// have an emitter. Both walk internal/check and cmd/sitegen. Neither looks at
// internal/ui, so the sample report the screenshots are made from was free to
// invent findings — and did.
//
// site/assets/tui.png, which is the terminal screenshot on the website and at
// the top of both READMEs, showed `ssh.maxauth` (the real ID is
// ssh.maxauthtries) and `fileperms.envfile` (there is no such finding). Four
// more were in the every-mode fixture. They had been there since the fixture
// was written, through every release, and nothing could see them:
// TestSiteFrameIsCurrent re-renders the frame and compares it byte for byte,
// so it pins that the picture matches the code that drew it — not that what
// the picture says is true. TestSiteFrameShowsWhatTheCaptionPromises reads the
// caption. No test read an ID.
//
// That is the same defect as a stale figure on the measurements page, in the
// one place a reader believes on sight and cannot check.
func TestEveryFindingIDInAFixtureIsOneHostveilCanReport(t *testing.T) {
	real := map[string]bool{}
	for _, id := range emittedFindingIDs(t) {
		real[id] = true
	}
	if len(real) < 20 {
		t.Fatalf("harvested only %d finding IDs from internal/check; the harvest is broken, "+
			"and a broken harvest makes this test pass on anything", len(real))
	}

	for _, hit := range fixtureFindingIDs(t) {
		if real[hit.id] {
			continue
		}
		t.Errorf("%s:%d names the finding %q, which no checker constructs.\n"+
			"  This fixture is drawn into a published screenshot, so the ID is a claim about\n"+
			"  what hostveil reports. Use an ID from internal/check, or teach a checker to\n"+
			"  emit this one.", hit.file, hit.line, hit.id)
	}
}

type fixtureHit struct {
	file string
	line int
	id   string
}

// fixtureIDPattern matches a namespaced finding ID wherever it appears — in a
// Go string literal, or in the ANSI capture the screenshot is rendered from.
//
// It is built from the real source names for the reason findings_test.go's own
// pattern is: a hand-written alternation is the thing this repo has most
// reliably got wrong, and here a stale one would silently stop checking a
// domain's fixtures.
var fixtureIDPattern = func() *regexp.Regexp {
	names := make([]string, 0, len(model.AllSources()))
	for _, s := range model.AllSources() {
		names = append(names, regexp.QuoteMeta(s.String()))
	}
	return regexp.MustCompile(`\b(` + strings.Join(names, "|") + `)\.[a-z0-9][a-z0-9.\-]*`)
}()

// notAFindingID rejects the one thing that looks exactly like a finding ID and
// is not: a filename whose stem happens to be a domain name.
//
// `docker-compose.yml` is all over the compose fixtures, and `compose` is a
// Source, so the pattern above matches `compose.yml`. The list is extensions
// rather than whole names because the collision is structural — any file the
// fixtures name could have a domain's word in front of the dot — and it is
// short because a finding ID never ends in one of these.
func notAFindingID(id string) bool {
	ext := id[strings.LastIndex(id, ".")+1:]
	return slices.Contains([]string{"yml", "yaml", "json", "json5", "conf", "sh", "go", "png", "ans"}, ext)
}

// fixtureRoots are the trees whose fixtures end up in front of a reader.
//
// internal/ui builds the two screenshots. scripts/ draws the social preview
// card, which is the image every link to this repository unfurls as — the
// same claim as the terminal screenshot, in the place with the widest reach
// and the least chance of anyone checking it.
var fixtureRoots = []string{
	filepath.Join("internal", "ui"),
	"scripts",
}

// fixtureFindingIDs collects every finding ID named anywhere under those
// trees, including testdata.
//
// Whole directories, not a list of files. A list is a thing to forget to add
// to, and the cost of over-collecting is only ever that a genuine ID has to be
// a genuine ID — which is the rule anyway. Production UI code does not name
// findings: it renders whatever the engine hands it.
func fixtureFindingIDs(t *testing.T) []fixtureHit {
	t.Helper()
	var out []fixtureHit
	for _, r := range fixtureRoots {
		out = append(out, walkForFindingIDs(t, filepath.Join(repoRoot(t), r))...)
	}
	if len(out) == 0 {
		t.Fatal("no finding IDs found in any fixture tree — the fixtures build the " +
			"screenshots from findings, so finding none means this test is looking in the wrong place")
	}
	return out
}

func walkForFindingIDs(t *testing.T, root string) []fixtureHit {
	t.Helper()
	var out []fixtureHit
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !slices.Contains([]string{".go", ".ans", ".json", ".py"}, filepath.Ext(path)) {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(repoRoot(t), path)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, id := range fixtureIDPattern.FindAllString(line, -1) {
				if notAFindingID(id) {
					continue
				}
				out = append(out, fixtureHit{file: filepath.ToSlash(rel), line: i + 1, id: id})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
