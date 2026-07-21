// Package docs tests that AGENTS.md still describes the code it claims to
// describe.
//
// AGENTS.md is the first thing a new contributor — human or agent — reads,
// and it restates things the code decides: which files hold which seam, how
// many checkers the engine builds, which linters run. Prose cannot fail a
// build, so those restatements go stale silently. They already did: the
// engine grew a ninth checker and the CI gate grew an actionlint step, and
// the file kept saying "eight" and omitting the step for a day, through two
// merges, with nobody noticing.
//
// These tests are deliberately narrow. They check claims that are mechanical
// and unambiguous — a path exists, a symbol is declared, a count matches, a
// list matches — and nothing about the prose. Rewording an invariant must
// never fail a build; renaming the thing it names must.
package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// repoRoot walks up from the test's directory to the module root, so the
// tests read the real AGENTS.md rather than an embedded copy that could
// itself drift.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above the test directory")
		}
		dir = parent
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func agentsMD(t *testing.T) string { return readRepoFile(t, "AGENTS.md") }

var (
	// Fenced blocks must be removed before inline spans are extracted. A
	// fence is three backticks, so a naive inline pattern pairs the fence's
	// backticks with each other and swallows the whole block as one span —
	// which then looks like prose and is skipped, silently taking every real
	// reference near it along. That bug made an earlier version of this file
	// see 1 path reference where there are 14.
	fencedBlock = regexp.MustCompile("(?s)```.*?```")
	// No newline in the class, so an unbalanced backtick cannot run away
	// across half the document.
	inlineCode = regexp.MustCompile("`([^`\n]+)`")
	// Paths as they appear inside command blocks: `scripts/bench.sh`,
	// `./cmd/sitegen`, `internal/check/ssh`. Anchored on a real top-level
	// directory so flags and `./...` cannot match.
	commandPath = regexp.MustCompile(`(?m)(?:^|\s)\.?/?((?:cmd|internal|demo|docs|scripts|site|test)/[A-Za-z0-9._/-]*)`)
)

func addUnique(out []string, s string) []string {
	if s != "" && !slices.Contains(out, s) {
		return append(out, s)
	}
	return out
}

// tokens returns every distinct inline-code span in AGENTS.md, with fenced
// code blocks removed first.
func tokens(t *testing.T) []string {
	t.Helper()
	prose := fencedBlock.ReplaceAllString(agentsMD(t), "")
	var out []string
	for _, m := range inlineCode.FindAllStringSubmatch(prose, -1) {
		out = addUnique(out, m[1])
	}
	return out
}

// commandPaths returns repo paths named inside the fenced command blocks.
// Those blocks are what a contributor copies and runs, so a path that has
// moved out from under one is worth catching too.
func commandPaths(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, block := range fencedBlock.FindAllString(agentsMD(t), -1) {
		for _, m := range commandPath.FindAllStringSubmatch(block, -1) {
			// Keep any trailing slash: it is what marks `site/` as a
			// directory rather than a bare filename to go hunting for.
			out = addUnique(out, m[1])
		}
	}
	return out
}

// repoDirs are the top-level directories a path reference can start with.
// Requiring one is what keeps this from trying to resolve prose: `core`,
// `app.go`, and `pages.json` are all real things written relative to some
// context the doc establishes in words, and guessing at them would produce
// failures that say nothing.
var repoDirs = []string{"cmd/", "internal/", "demo/", "docs/", "scripts/", "site/", "test/"}

var (
	// bareFile matches a filename written without a directory, like
	// `pages.json` or `app.go`. The doc names these relative to a directory
	// it established in the surrounding prose, so they are resolved by
	// searching the tree rather than by guessing at that context.
	bareFile = regexp.MustCompile(`^[A-Za-z0-9._-]+\.(md|yaml|yml|json|sh|go|tmpl)$`)
	// pkgQualified matches a package path with an exported symbol hung off
	// it — `internal/core.Engine`. It reads as a path but the last segment
	// is not a file, so only the package directory can be stat'ed.
	pkgQualified = regexp.MustCompile(`^(.*/[a-z][a-z0-9]*)\.[A-Z]\w*$`)
)

func isPathRef(tok string) bool {
	if strings.ContainsAny(tok, " \t(=") {
		return false // prose or a code fragment, not a path
	}
	if bareFile.MatchString(tok) {
		return true
	}
	for _, d := range repoDirs {
		if strings.HasPrefix(tok, d) {
			return true
		}
	}
	return false
}

// resolve turns a reference into the path to stat, and reports whether the
// name may be found anywhere in the tree rather than at that exact location.
func resolve(tok string) (path string, anywhere bool) {
	if m := pkgQualified.FindStringSubmatch(tok); m != nil {
		return m[1], false // check the package dir, not the symbol
	}
	if !strings.Contains(tok, "/") {
		return tok, true // a bare filename: the doc's context says where
	}
	// A glob (`site/**/*.html`) cannot be stat'ed, and expanding `**`
	// correctly is not worth it — checking the fixed prefix catches the
	// failure that actually happens, which is the tree being moved out from
	// under the pattern.
	if i := strings.IndexAny(tok, "*{"); i >= 0 {
		tok = tok[:i]
	}
	return strings.TrimSuffix(tok, "/"), false
}

// existsAnywhere reports whether a file with this basename exists in the
// repo, ignoring directories that are not ours to describe.
func existsAnywhere(t *testing.T, root, name string) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil //nolint:nilerr // an unreadable subtree is not a doc defect
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", ".vagrant":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == name {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return found
}

// TestReferencedPathsExist is the check that earns its keep on an ordinary
// day: files get renamed and moved constantly, and a doc that points at
// somewhere no longer there sends a contributor hunting.
func TestReferencedPathsExist(t *testing.T) {
	root := repoRoot(t)

	refs := commandPaths(t)
	for _, tok := range tokens(t) {
		if isPathRef(tok) {
			refs = addUnique(refs, tok)
		}
	}
	// A guard against this test quietly checking nothing, which is exactly
	// how it failed before: the extraction broke, every reference vanished,
	// and it went on passing.
	if len(refs) < 10 {
		t.Fatalf("only %d path references extracted from AGENTS.md (%v) — extraction is broken, not the doc", len(refs), refs)
	}

	for _, tok := range refs {
		p, anywhere := resolve(tok)
		if p == "" {
			continue
		}
		if anywhere {
			if !existsAnywhere(t, root, p) {
				t.Errorf("AGENTS.md references %q, but no file named %s exists in the repo", tok, p)
			}
			continue
		}
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("AGENTS.md references %q, but %s does not exist", tok, p)
		}
	}
}

// pkgRef matches `pkg.Symbol`, where Symbol is exported. The uppercase
// requirement is load-bearing: finding IDs are spelled the same way
// (`compose.ds016`, `cve.*`) and are emphatically not Go symbols.
var pkgRef = regexp.MustCompile(`^([a-z][a-z0-9]*)\.([A-Z][A-Za-z0-9_]*)(\(\))?$`)

// declaredNames returns every top-level name the .go files in dir declare —
// funcs and methods, types, vars, and consts.
//
// The files are parsed one at a time rather than with parser.ParseDir, which
// is deprecated: it ignores build tags when grouping files into packages.
// Nothing here needs that grouping, since a name declared anywhere in the
// directory is a name the doc may legitimately reference.
func declaredNames(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	names := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				names[d.Name.Name] = true
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						names[s.Name.Name] = true
					case *ast.ValueSpec:
						for _, n := range s.Names {
							names[n.Name] = true
						}
					}
				}
			}
		}
	}
	return names
}

// TestReferencedSymbolsExist catches the rename that a path check cannot: the
// file stays put, but the thing inside it the doc named is gone.
func TestReferencedSymbolsExist(t *testing.T) {
	root := repoRoot(t)
	checked := 0
	for _, tok := range tokens(t) {
		m := pkgRef.FindStringSubmatch(tok)
		if m == nil {
			continue
		}
		pkg, symbol := m[1], m[2]
		dir := filepath.Join(root, "internal", pkg)
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue // not a reference to an internal package
		}
		checked++
		if !declaredNames(t, dir)[symbol] {
			t.Errorf("AGENTS.md references %q, but internal/%s declares no %s", tok, pkg, symbol)
		}
	}
	// Same guard as the path test, for the same reason.
	if checked < 5 {
		t.Fatalf("only %d package symbols extracted from AGENTS.md — extraction is broken, not the doc", checked)
	}
}

// numberWords covers the range a checker count could plausibly reach. Writing
// the count as a word is the natural prose, so the test meets the prose where
// it is rather than forcing a digit into the sentence.
var numberWords = map[string]int{
	"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
	"eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
	"fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
	"nineteen": 19, "twenty": 20,
}

var (
	documentedCheckers  = regexp.MustCompile(`all (\w+) checkers`)
	checkerRegistration = regexp.MustCompile(`\b[a-z]+check\.New\(\)`)
)

// TestDocumentedCheckerCountMatchesTheEngine pins the exact claim that went
// stale when the agent domain landed.
func TestDocumentedCheckerCountMatchesTheEngine(t *testing.T) {
	m := documentedCheckers.FindStringSubmatch(agentsMD(t))
	if m == nil {
		t.Fatal(`AGENTS.md no longer says "all N checkers" — update this test if the wording moved on purpose`)
	}
	want, ok := numberWords[strings.ToLower(m[1])]
	if !ok {
		t.Fatalf("AGENTS.md says %q checkers, which is not a number word this test knows", m[1])
	}
	got := len(checkerRegistration.FindAllString(readRepoFile(t, "cmd/hostveil/app.go"), -1))
	if got != want {
		t.Errorf("AGENTS.md says the engine builds %s (%d) checkers, but cmd/hostveil/app.go registers %d",
			m[1], want, got)
	}
}

var (
	documentedLinters = regexp.MustCompile(`enables only ([^.]+)\.`)
	enabledLinter     = regexp.MustCompile(`(?m)^\s*-\s*(\w+)\s*$`)
)

// TestDocumentedLintersMatchTheConfig keeps the doc honest about what the
// lint gate actually enforces — a contributor who trusts a stale list writes
// code expecting checks that are not running.
func TestDocumentedLintersMatchTheConfig(t *testing.T) {
	m := documentedLinters.FindStringSubmatch(agentsMD(t))
	if m == nil {
		t.Fatal(`AGENTS.md no longer says which linters the config "enables only"`)
	}
	var documented []string
	for _, l := range strings.Split(m[1], ",") {
		if l = strings.Trim(strings.TrimSpace(l), "`"); l != "" {
			documented = append(documented, l)
		}
	}

	cfg := readRepoFile(t, ".golangci.yaml")
	_, after, found := strings.Cut(cfg, "enable:")
	if !found {
		t.Fatal(".golangci.yaml has no enable: list")
	}
	var enabled []string
	for _, m := range enabledLinter.FindAllStringSubmatch(after, -1) {
		enabled = append(enabled, m[1])
	}

	slices.Sort(documented)
	slices.Sort(enabled)
	if !slices.Equal(documented, enabled) {
		t.Errorf("AGENTS.md documents linters %v, but .golangci.yaml enables %v", documented, enabled)
	}
}

// TestClaudeMdImportsAgentsMd guards the wiring that makes this file reach
// Claude Code at all. Claude Code does not read AGENTS.md natively, so the
// import in CLAUDE.md is the only thing connecting them — and CLAUDE.md now
// looks so much like a redundant stub that deleting it is the obvious
// tidy-up. It is not: the guidance would silently stop loading.
func TestClaudeMdImportsAgentsMd(t *testing.T) {
	claude := readRepoFile(t, "CLAUDE.md")
	for _, line := range strings.Split(claude, "\n") {
		if strings.TrimSpace(line) == "@AGENTS.md" {
			return
		}
	}
	t.Error("CLAUDE.md must contain a bare `@AGENTS.md` import line, or Claude Code loads no project guidance at all")
}

var documentedPRScopes = regexp.MustCompile(`accepts only ([^.]+)\.`)

// TestDocumentedPRScopesMatchTheWorkflow pins the scope allowlist. The list
// is not discoverable from the convention it implements: conventional
// commits allows any scope, so `fix(check/ssh):` looks correct, reads
// correct, and is rejected only after the pull request is already open. The
// doc had described where the component goes without saying that the set of
// legal values is closed, which is most of what a contributor needs.
func TestDocumentedPRScopesMatchTheWorkflow(t *testing.T) {
	m := documentedPRScopes.FindStringSubmatch(agentsMD(t))
	if m == nil {
		t.Fatal(`AGENTS.md no longer says which scopes pr-title.yml "accepts only"`)
	}
	var documented []string
	for _, s := range strings.Split(m[1], ",") {
		if s = strings.Trim(strings.TrimSpace(s), "`"); s != "" {
			documented = append(documented, s)
		}
	}

	wf := readRepoFile(t, filepath.Join(".github", "workflows", "pr-title.yml"))
	_, after, found := strings.Cut(wf, "scopes: |")
	if !found {
		t.Fatal("pr-title.yml has no scopes: block")
	}
	var allowed []string
	for _, line := range strings.Split(after, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, ":") || strings.HasPrefix(line, "#") {
			break // the next YAML key ends the block scalar
		}
		allowed = append(allowed, line)
	}
	if len(allowed) == 0 {
		t.Fatal("parsed no scopes from pr-title.yml; the workflow markup changed")
	}

	slices.Sort(documented)
	slices.Sort(allowed)
	if !slices.Equal(documented, allowed) {
		t.Errorf("AGENTS.md documents scopes %v, but pr-title.yml allows %v", documented, allowed)
	}
}
