// The community-health files are read by GitHub and by people, never by the
// compiler, so like AGENTS.md they go stale silently — with the extra hazard
// that GitHub degrades a malformed file instead of rejecting it. An issue
// form with a YAML error falls back to a blank editor, which quietly reopens
// the exact hole `blank_issues_enabled: false` exists to close: security
// reports arriving as public issues. Same policy as agents_test.go — check
// what is mechanical, never the prose.
package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestIssueFormsAreWellFormed pins what GitHub actually requires of an issue
// form: parseable YAML, a name and description, and a non-empty body whose
// every element declares a type. Anything less renders as a broken template
// chooser with no error surfaced to anyone.
func TestIssueFormsAreWellFormed(t *testing.T) {
	dir := filepath.Join(repoRoot(t), ".github", "ISSUE_TEMPLATE")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	forms := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}

		if name == "config.yml" || name == "config.yaml" {
			var cfg struct {
				BlankIssuesEnabled *bool `yaml:"blank_issues_enabled"`
				ContactLinks       []struct {
					Name  string `yaml:"name"`
					URL   string `yaml:"url"`
					About string `yaml:"about"`
				} `yaml:"contact_links"`
			}
			if err := yaml.Unmarshal(raw, &cfg); err != nil {
				t.Errorf("%s does not parse: %v", name, err)
				continue
			}
			// The explicit false is the point of the file: blank issues are
			// how a vulnerability report ends up public.
			if cfg.BlankIssuesEnabled == nil || *cfg.BlankIssuesEnabled {
				t.Errorf("%s must set blank_issues_enabled: false", name)
			}
			if len(cfg.ContactLinks) == 0 {
				t.Errorf("%s routes nowhere: no contact_links", name)
			}
			for i, l := range cfg.ContactLinks {
				if l.Name == "" || l.URL == "" || l.About == "" {
					t.Errorf("%s contact link %d is missing name, url, or about", name, i)
				}
			}
			continue
		}

		forms++
		var form struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
			Body        []struct {
				Type string `yaml:"type"`
			} `yaml:"body"`
		}
		if err := yaml.Unmarshal(raw, &form); err != nil {
			t.Errorf("%s does not parse: %v", name, err)
			continue
		}
		if form.Name == "" || form.Description == "" {
			t.Errorf("%s needs both a name and a description to appear in the chooser", name)
		}
		if len(form.Body) == 0 {
			t.Errorf("%s has no body elements", name)
		}
		for i, el := range form.Body {
			if el.Type == "" {
				t.Errorf("%s body element %d declares no type", name, i)
			}
		}
	}
	if forms == 0 {
		t.Fatal("no issue forms found — if they moved on purpose, move this test's directory too")
	}
}

// TestCitationFileMatchesTheRepo keeps CITATION.cff honest about the things
// the repo already states elsewhere: the module path names the repository,
// and LICENSE names the license. A citation pointing at a renamed repo or
// claiming the wrong license is worse than none.
func TestCitationFileMatchesTheRepo(t *testing.T) {
	var cff struct {
		CFFVersion     string `yaml:"cff-version"`
		Title          string `yaml:"title"`
		RepositoryCode string `yaml:"repository-code"`
		License        string `yaml:"license"`
		Authors        []any  `yaml:"authors"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "CITATION.cff")), &cff); err != nil {
		t.Fatalf("CITATION.cff does not parse: %v", err)
	}
	if cff.CFFVersion == "" {
		t.Error("CITATION.cff declares no cff-version, so GitHub will not offer the cite button")
	}
	if cff.Title == "" || len(cff.Authors) == 0 {
		t.Error("CITATION.cff needs a title and at least one author to be a citation")
	}

	m := regexp.MustCompile(`(?m)^module\s+(\S+)`).FindStringSubmatch(readRepoFile(t, "go.mod"))
	if m == nil {
		t.Fatal("go.mod has no module line")
	}
	if !strings.Contains(cff.RepositoryCode, m[1]) {
		t.Errorf("CITATION.cff points at %q, but the module is %q", cff.RepositoryCode, m[1])
	}

	// LICENSE is the GPL text; its title line is enough to anchor the SPDX
	// family without parsing the whole document.
	if !strings.Contains(readRepoFile(t, "LICENSE"), "GNU GENERAL PUBLIC LICENSE") ||
		!strings.HasPrefix(cff.License, "GPL-3.0") {
		t.Errorf("CITATION.cff says license %q, which does not match LICENSE", cff.License)
	}
}

var (
	mdImage   = regexp.MustCompile(`!\[[^\]]*\]\(([^)\s]+)`)
	htmlImage = regexp.MustCompile(`<img[^>]+src="([^"]+)"`)
	mdLink    = regexp.MustCompile(`[^!]\[[^\]]*\]\(([^)\s]+)`)
)

// TestReadmeLocalReferencesExist does for README.md what
// TestReferencedPathsExist does for AGENTS.md: every repo-relative image and
// link must resolve. The hero screenshot is the first thing the project page
// shows, and a moved PNG turns it into a broken-image icon with no CI signal.
func TestReadmeLocalReferencesExist(t *testing.T) {
	root := repoRoot(t)
	for _, path := range []string{"README.md", "README.ko.md"} {
		readme := readRepoFile(t, path)

		var refs []string
		for _, re := range []*regexp.Regexp{mdImage, htmlImage, mdLink} {
			for _, m := range re.FindAllStringSubmatch(readme, -1) {
				target := m[1]
				if strings.Contains(target, "://") || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:") {
					continue
				}
				target, _, _ = strings.Cut(target, "#")
				refs = addUnique(refs, target)
			}
		}
		// The same nothing-extracted guard as the AGENTS.md tests: each README
		// links at least its license, module file, and two screenshots today.
		if len(refs) < 3 {
			t.Fatalf("only %d local references extracted from %s (%v) — extraction is broken, not the doc", len(refs), path, refs)
		}
		for _, ref := range refs {
			if _, err := os.Stat(filepath.Join(root, ref)); err != nil {
				t.Errorf("%s references %q, which does not exist", path, ref)
			}
		}
	}
}

// TestPRTemplateGateMatchesAgentsMd pins the CI-gate commands the pull
// request template tells a contributor to run to the ones AGENTS.md
// documents. The template repeats them because a contributor sees it at the
// exact moment the commands matter; repetition is only safe while this keeps
// the copies identical — a version bumped in one file and not the other has
// contributors running a gate CI no longer runs.
func TestPRTemplateGateMatchesAgentsMd(t *testing.T) {
	tmpl := readRepoFile(t, filepath.Join(".github", "pull_request_template.md"))
	agents := agentsMD(t)

	blocks := fencedBlock.FindAllString(tmpl, -1)
	if len(blocks) == 0 {
		t.Fatal("the pull request template no longer has a fenced command block")
	}
	checked := 0
	for _, line := range strings.Split(strings.Trim(blocks[0], "`"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		checked++
		if !strings.Contains(agents, line) {
			t.Errorf("the pull request template says to run %q, which AGENTS.md does not document", line)
		}
	}
	if checked < 3 {
		t.Fatalf("only %d gate commands extracted from the template — extraction is broken, not the doc", checked)
	}
}
