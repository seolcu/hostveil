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
	"cmdScan":     "scan",
	"cmdFix":      "fix",
	"cmdRollback": "rollback",
	"cmdExplain":  "explain",
	"cmdServe":    "serve",
	"cmdTUI":      "tui",
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
