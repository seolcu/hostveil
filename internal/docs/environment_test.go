package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The environment-variable reference exists because a dozen variables were
// scattered across five pages with no reference anywhere, and two — the ones
// that decide whether hostveil re-executes itself as root — were documented
// nowhere user-facing at all. cmd/hostveil/elevate_test.go asserted, in a
// failure message, that "HOSTVEIL_ELEVATED is documented", which was not true
// of anything a user could read.
//
// A reference page's failure mode is omission, and omission is invisible: the
// page looks complete either way. So this harvests what hostveil's own code
// reads and requires every name to appear on the page.
//
// It covers hostveil's own reads only. The terminal libraries underneath the
// TUI read a dozen more — TERM, COLORTERM, TEA_TRACE and the rest — and those
// are on the page too, but they cannot be harvested from this tree and their
// absence would not be caught here. That gap is stated rather than papered
// over: the page's own note says which rows come from a dependency.
var hostveilVar = regexp.MustCompile(`<code>(HOSTVEIL_[A-Z0-9_]+)</code>`)

func TestEveryVariableHostveilReadsIsDocumented(t *testing.T) {
	page := readRepoFile(t, filepath.Join("cmd", "sitegen", "content", "en", "docs", "environment.html"))
	ko := readRepoFile(t, filepath.Join("cmd", "sitegen", "content", "ko", "docs", "environment.html"))

	for _, name := range readEnvNames(t) {
		if !strings.Contains(page, "<code>"+name+"</code>") {
			t.Errorf("hostveil reads %s and the environment reference does not list it — "+
				"a reference page that is missing a row looks exactly like a complete one", name)
		}
		if !strings.Contains(ko, "<code>"+name+"</code>") {
			t.Errorf("the Korean environment reference does not list %s", name)
		}
	}
}

// And `--help`, which is the reference a user reaches without a browser.
//
// The site pages were pinned and `--help` was not, so it drifted: --layout and
// HOSTVEIL_LAYOUT existed, worked, and were documented in the README and on
// the site, while the built-in help listed --theme and --glyphs and said
// nothing about them. cmd/hostveil/layout.go calls HOSTVEIL_LAYOUT "the
// counterpart of HOSTVEIL_THEME and HOSTVEIL_GLYPHS", which is exactly the
// claim `--help` was contradicting.
func TestEveryVariableHostveilReadsIsInTheBuiltInHelp(t *testing.T) {
	help := readRepoFile(t, filepath.Join("cmd", "hostveil", "main.go"))
	// Only the ones a person sets deliberately. The elevation guards and the
	// debug switch are documented on the site; --help is a short page and
	// listing every internal variable would bury the four that matter.
	for _, name := range []string{"HOSTVEIL_THEME", "HOSTVEIL_GLYPHS", "HOSTVEIL_LAYOUT", "HOSTVEIL_NO_SUDO"} {
		if !strings.Contains(help, name) {
			t.Errorf("`hostveil help` does not mention %s", name)
		}
	}
	// And the flags those variables override, for the same reason: a flag
	// missing from --help is a feature the only offline reference denies.
	for _, flag := range []string{"--theme", "--glyphs", "--layout", "--addr"} {
		if !strings.Contains(help, flag+" ") {
			t.Errorf("`hostveil help` does not document %s", flag)
		}
	}
}

// And the reverse. A row for a variable nothing reads is advice that cannot
// work — the reader sets it, nothing happens, and the page is the reason they
// tried.
//
// Only HOSTVEIL_-prefixed names are checked in this direction: everything
// else on the page is either read by a dependency or deliberately listed as
// *not* read (DOCKER_HOST, LANGUAGE), and this test cannot tell those apart.
func TestNoHostveilVariableIsDocumentedButUnread(t *testing.T) {
	page := readRepoFile(t, filepath.Join("cmd", "sitegen", "content", "en", "docs", "environment.html"))
	read := readEnvNames(t)

	documented := map[string]bool{}
	for _, m := range hostveilVar.FindAllStringSubmatch(page, -1) {
		documented[m[1]] = true
	}
	if len(documented) < 4 {
		t.Fatalf("only %d HOSTVEIL_ variables parsed from the reference (%v) — the extraction "+
			"is broken, not the page", len(documented), documented)
	}
	for name := range documented {
		if !slices.Contains(read, name) {
			t.Errorf("the environment reference documents %s but nothing in hostveil reads it — "+
				"a reader who sets it gets nothing, and the page is why they tried", name)
		}
	}
}

// readEnvNames harvests the variable names hostveil's own code reads.
//
// It resolves single-assignment consts, because two of the names are held
// that way (themeEnv, glyphsEnv) and a harvest that only looked at call
// arguments would miss exactly the two variables a user is most likely to
// set. It also follows one level of indirection through a helper whose first
// parameter is the key, which is how internal/ai reads its two.
func readEnvNames(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	fset := token.NewFileSet()
	consts := map[string]string{}
	var files []*ast.File

	for _, dir := range []string{"cmd/hostveil", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("parse %s: %v", path, perr)
			}
			files = append(files, f)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				if s, ok := envStringLit(vs.Values[0]); ok {
					consts[vs.Names[0].Name] = s
				}
			}
		}
	}

	var names []string
	add := func(n ast.Expr) {
		switch arg := n.(type) {
		case *ast.BasicLit:
			if s, ok := envStringLit(arg); ok {
				names = append(names, s)
			}
		case *ast.Ident:
			if s, ok := consts[arg.Name]; ok {
				names = append(names, s)
			}
		case *ast.SelectorExpr:
			// os.Getenv(tui.LayoutEnv) — a const another package exports.
			// Without this arm the read is invisible here and the variable
			// goes undocumented with both tests still passing, which is the
			// failure mode this file exists to prevent, one level up.
			//
			// consts is flat and keyed by name rather than by package, so two
			// packages exporting the same const name would collide. They do
			// not today, and a collision would have to be between two names
			// whose values both start with HOSTVEIL_ to matter at all.
			if s, ok := consts[arg.Sel.Name]; ok {
				names = append(names, s)
			}
		}
	}

	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "os" &&
					(fn.Sel.Name == "Getenv" || fn.Sel.Name == "LookupEnv") {
					add(call.Args[0])
				}
			case *ast.Ident:
				// envOr(key, default) in internal/ai: the key is arg 0.
				if fn.Name == "envOr" {
					add(call.Args[0])
				}
				// getenv("X") where getenv is an injected func(string) string,
				// which is how this repository tests anything that reads the
				// environment. sshHint takes os.Getenv as a parameter, so the
				// name it reads appeared in no os.Getenv call anywhere and
				// this page could have gone on omitting it with every test
				// here green.
				if strings.EqualFold(fn.Name, "getenv") || strings.EqualFold(fn.Name, "lookupenv") {
					add(call.Args[0])
				}
			}
			return true
		})
	}
	slices.Sort(names)
	names = slices.Compact(names)

	// Nothing-extracted guard. hostveil reads several; a harvest that stopped
	// matching would make both tests above pass while checking nothing.
	if len(names) < 6 {
		t.Fatalf("only %d environment reads harvested (%v) — the harvest is broken, not the page",
			len(names), names)
	}
	return names
}

func envStringLit(n ast.Node) (string, bool) {
	lit, ok := n.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}
