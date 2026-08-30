package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/selfupdate"
)

// The CLI reference on the website restates this package's flag sets, and
// nothing checked the restatement. It was wrong in both directions at once:
// the fix table listed a --no-color flag that does not exist (typing it exits
// 2), and rollback was documented as taking no flags months after --force was
// added — the flag that stands between an operator and an unrecoverable
// overwrite of their own edits.
//
// Prose cannot fail a build. This gives it a way to.

// docSection maps a function in this package to the <h2 id="…"> section of
// the CLI reference that documents it.
var docSection = map[string]string{
	"cmdScan":        "scan",
	"cmdFix":         "fix",
	"cmdRollback":    "rollback",
	"cmdExplain":     "explain",
	"cmdExport":      "export",
	"cmdServe":       "serve",
	"cmdTUI":         "tui",
	"cmdHistory":     "history",
	"cmdDiagnostics": "diagnostics",
	"cmdUpdate":      "update",
	"cmdUninstall":   "uninstall",
}

var docLangs = []string{"en", "ko"}

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

// declaredFlags walks this package's own source for the flag names each
// subcommand registers. Reading the AST rather than the flag.FlagSet values
// keeps the production code free of test seams: the flag sets are built
// inside the cmd functions, which cannot be called without running the
// command they belong to.
func declaredFlags(t *testing.T) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	out := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			section, documented := docSection[fn.Name.Name]
			if !documented {
				continue
			}
			// Seed the section even when the command registers nothing, so
			// "documented as taking no flags" is a checked claim rather
			// than an absence. `history` is the case: it accepted no flags
			// and also parsed none, so an unknown one was silently ignored
			// instead of exiting 2 like every other subcommand.
			if _, ok := out[section]; !ok {
				out[section] = []string{}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if flag := flagNameOf(n); flag != "" {
					out[section] = append(out[section], flag)
				}
				return true
			})
		}
	}
	for section := range out {
		slices.Sort(out[section])
	}
	return out
}

// flagNameOf returns the flag registered by a `fs.Bool("name", …)` or
// `fs.StringVar(&v, "name", …)` call, or "" for anything else.
func flagNameOf(n ast.Node) string {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok || recv.Name != "fs" {
		return ""
	}
	// The *Var forms take the destination pointer first.
	arg := 0
	if strings.HasSuffix(sel.Sel.Name, "Var") {
		arg = 1
	}
	if len(call.Args) <= arg {
		return ""
	}
	lit, ok := call.Args[arg].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	name, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return name
}

var (
	// <h2 id="scan"> … up to the next <h2, i.e. one subcommand's section.
	docHeading = regexp.MustCompile(`<h2 id="([a-z-]+)">`)
	// The first cell of a table row, which is where a flag table puts the
	// flag: <tr><td><code>--action N</code></td>… Prose mentions of a flag
	// are outside a <tr>, so they cannot be mistaken for documentation of one.
	flagCell = regexp.MustCompile(`<tr><td>((?:<code>-[^<]*</code>\s*,?\s*)+)</td>`)
	flagName = regexp.MustCompile(`<code>(--?[A-Za-z0-9][A-Za-z0-9-]*)[^<]*</code>`)
)

// documentedFlags extracts the flags each subcommand section lists.
func documentedFlags(t *testing.T, lang string) map[string][]string {
	t.Helper()
	page, err := os.ReadFile(filepath.Join(repoRoot(t), "cmd", "sitegen", "content", lang, "docs", "cli.html"))
	if err != nil {
		t.Fatalf("read %s CLI reference: %v", lang, err)
	}
	html := string(page)

	headings := docHeading.FindAllStringSubmatchIndex(html, -1)
	if len(headings) == 0 {
		t.Fatalf("%s: no <h2 id=…> sections parsed; the page markup changed", lang)
	}

	out := map[string][]string{}
	for i, h := range headings {
		section := html[h[2]:h[3]]
		end := len(html)
		if i+1 < len(headings) {
			end = headings[i+1][0]
		}
		for _, cell := range flagCell.FindAllStringSubmatch(html[h[1]:end], -1) {
			for _, m := range flagName.FindAllStringSubmatch(cell[1], -1) {
				out[section] = append(out[section], strings.TrimLeft(m[1], "-"))
			}
		}
		slices.Sort(out[section])
	}
	return out
}

func TestCLIReferenceMatchesTheFlagSets(t *testing.T) {
	declared := declaredFlags(t)
	if len(declared) != len(docSection) {
		t.Fatalf("found flag sets for %d of %d subcommands: %v", len(declared), len(docSection), declared)
	}

	for _, lang := range docLangs {
		documented := documentedFlags(t, lang)
		for section, want := range declared {
			got := documented[section]
			for _, flag := range want {
				if !slices.Contains(got, flag) {
					t.Errorf("%s: `hostveil %s` accepts --%s but the CLI reference does not list it",
						lang, section, flag)
				}
			}
			for _, flag := range got {
				if !slices.Contains(want, flag) {
					t.Errorf("%s: the CLI reference lists --%s for `hostveil %s`, which does not accept it — "+
						"a reader who types it gets exit 2", lang, flag, section)
				}
			}
		}
	}
}

// A subcommand with no section at all would slip past the comparison above,
// since an absent section documents an empty set of flags for a command that
// may well have none.
func TestEverySubcommandHasAReferenceSection(t *testing.T) {
	for _, lang := range docLangs {
		documented := documentedFlags(t, lang)
		page, err := os.ReadFile(filepath.Join(repoRoot(t), "cmd", "sitegen", "content", lang, "docs", "cli.html"))
		if err != nil {
			t.Fatal(err)
		}
		for _, section := range docSection {
			if !strings.Contains(string(page), `<h2 id="`+section+`">`) {
				t.Errorf("%s: the CLI reference has no section for `hostveil %s`", lang, section)
			}
		}
		_ = documented
	}
}

// Every subcommand this package defines has to be classified and documented.
//
// Both lists that decide those things are hand-maintained maps — docSection
// here, and needsRoot's switch — and adding a subcommand fails neither of
// them. A command that nobody added to needsRoot runs unprivileged and
// discovers it needed root half way through; one nobody added to the CLI
// reference is a command users find by reading the help text and nowhere else.
//
// The harvest is from the dispatch switch rather than from function names, so
// a cmdXxx helper that is not a subcommand does not have to be excused here.
func TestEverySubcommandIsClassifiedAndDocumented(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	dispatched := map[string]string{} // command name -> handler
	ast.Inspect(file, func(n ast.Node) bool {
		cl, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		var handler string
		ast.Inspect(cl, func(m ast.Node) bool {
			if call, ok := m.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && strings.HasPrefix(id.Name, "cmd") {
					handler = id.Name
				}
			}
			return true
		})
		if handler == "" {
			return true
		}
		for _, e := range cl.List {
			if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if name, err := strconv.Unquote(lit.Value); err == nil {
					dispatched[name] = handler
				}
			}
		}
		return true
	})
	if len(dispatched) < 7 {
		t.Fatalf("harvested only %d subcommands from the dispatch switch; the walk is broken", len(dispatched))
	}

	for name, handler := range dispatched {
		if !needsRoot(name) {
			t.Errorf("%q dispatches to %s and needsRoot says it does not need root; "+
				"if that is right, add it to the print-only list in cli_test.go and say why here",
				name, handler)
		}
		if _, ok := docSection[handler]; !ok {
			t.Errorf("%s handles %q and has no entry in docSection, so the CLI reference is not "+
				"checked for it in either language", handler, name)
		}
	}
}

// The version this binary is stamped with and the version the updater resolves
// have to compare equal when they are the same release.
//
// They are produced by different things and disagree about the leading v:
// goreleaser passes `-X main.version=v{{.Version}}`, and the updater trims the
// tag because an asset URL needs it trimmed. Comparing them raw is never true,
// and the symptom is that `hostveil update` on a current host announces an
// update and reinstalls what is already there.
//
// Pinned against the real `version` variable rather than a literal, so a change
// to how the build stamps it lands here.
func TestTheStampedVersionComparesAgainstAResolvedTag(t *testing.T) {
	stamped := version
	if !strings.HasPrefix(stamped, "v") {
		t.Fatalf("version = %q; goreleaser stamps a leading v and this test is about that", stamped)
	}
	resolved := strings.TrimPrefix(stamped, "v")
	if !selfupdate.SameVersion(stamped, resolved) {
		t.Errorf("SameVersion(%q, %q) is false, so `hostveil update` would offer the version it is running",
			stamped, resolved)
	}
}

// The update path needs two HTTP clients with opposite redirect behaviour, and
// sharing one is a bug that hides until the first real download.
//
// Latest learns the version from the Location header of /releases/latest, so
// its client must not follow redirects. A release asset URL answers 302 and
// sends the caller to objects.githubusercontent.com, so the download client
// must. One shared no-redirect client made every download fail with "returned
// 302 Found" — on the one path a `--check` smoke test never reaches, which is
// exactly how it survived being tested.
func TestTheUpdateClientsDisagreeAboutRedirectsOnPurpose(t *testing.T) {
	if resolveClient().CheckRedirect == nil {
		t.Error("the resolving client follows redirects, so Latest would read the release page instead of the tag")
	}
	if downloadClient().CheckRedirect != nil {
		t.Error("the download client does not follow redirects, so every asset download fails on GitHub's 302")
	}
}

// TestTheBuiltInHelpDocumentsEveryFlag.
//
// The site's flag tables are held to the flag sets by the test above, and
// `hostveil help` was held to a hand-written list of four flags — so six
// drifted out of it and nothing said anything. `fix --review`,
// `history --scans`, `update --yes` and `uninstall --yes` all existed,
// worked, and were absent from the only reference a user has without a
// browser; the `--all` line went further and stated that Review fixes are
// left alone, which `--review` had made untrue.
//
// The site pages and the built-in help are the same claim in two places, and
// only one of them was pinned. This is the other one.
func TestTheBuiltInHelpDocumentsEveryFlag(t *testing.T) {
	help, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(help)

	declared := declaredFlags(t)
	if len(declared) == 0 {
		t.Fatal("no flag sets found; the harvest is broken and this test would pass on anything")
	}
	for section, flags := range declared {
		for _, flag := range flags {
			if !strings.Contains(text, "--"+flag) {
				t.Errorf("`hostveil %s` accepts --%s and `hostveil help` never mentions it.\n"+
					"  help is the reference a user reaches without a browser, and a flag missing "+
					"from it is a feature the offline documentation denies.", section, flag)
			}
		}
	}
}
