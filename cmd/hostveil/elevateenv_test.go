package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The re-exec discards every variable a user set, and always has.
//
// sudo's env_reset keeps only what env_keep names — TERM, LANG, LC_* and a
// short list — never an application's own. alreadyElevated's comment says so,
// and drew the conclusion about exactly one variable: the marker this code
// used to pass itself. It applies identically to every variable a user sets
// on hostveil's own command line.
//
// So the line hostveil documents most loudly did nothing.
// `HOSTVEIL_DEBUG=1 hostveil scan` appears in `hostveil help`, in the README
// and on both troubleshooting pages as the thing to attach to a bug report,
// and on the ordinary non-root host it produced no trace, no error, and no
// hint that the variable had been dropped. HOSTVEIL_THEME and HOSTVEIL_GLYPHS
// were ignored the same way.
//
// The end-to-end job never caught it because it runs as root with
// HOSTVEIL_NO_SUDO=1 — both of the branches that skip the re-exec.
func TestElevationCarriesTheVariablesTheUserSet(t *testing.T) {
	set := map[string]string{
		"HOSTVEIL_DEBUG":  "1",
		"HOSTVEIL_THEME":  "nord",
		"HOSTVEIL_GLYPHS": "nerd",
	}
	argv := append(elevatedArgv("/usr/local/bin/hostveil", nil, func(k string) string { return set[k] }),
		"scan", "--json")

	if argv[0] != "sudo" {
		t.Fatalf("argv does not start with sudo: %v", argv)
	}
	for name, want := range set {
		if !slices.Contains(argv, name+"="+want) {
			t.Errorf("%s=%s is not carried across the re-exec; the child will not see it:\n  %v",
				name, want, argv)
		}
	}

	// Order matters to sudo: assignments come before the command, and the
	// command's own arguments after it. Getting this wrong turns a variable
	// into an argument hostveil then rejects as an unknown flag.
	exe := slices.Index(argv, "/usr/local/bin/hostveil")
	if exe < 0 {
		t.Fatalf("the executable is missing from argv: %v", argv)
	}
	for i, a := range argv[1:exe] {
		if !strings.Contains(a, "=") {
			t.Errorf("argv[%d] = %q sits before the executable but is not an assignment", i+1, a)
		}
	}
	if got := argv[exe+1:]; !slices.Equal(got, []string{"scan", "--json"}) {
		t.Errorf("the command's arguments were disturbed: %v", got)
	}
}

// A host with none of them set must build exactly the argv it built before
// this existed. The re-exec is on the path every non-root user takes, and a
// change there that is not opt-in is a change to how hostveil starts.
func TestElevationIsUnchangedWhenNothingIsSet(t *testing.T) {
	argv := elevatedArgv("/usr/local/bin/hostveil", nil, func(string) string { return "" })
	if !slices.Equal(argv, []string{"sudo", "/usr/local/bin/hostveil"}) {
		t.Errorf("argv = %v, want just sudo and the binary", argv)
	}
}

// TestEveryReadVariableIsCarriedOrExcusedOnPurpose closes the loop from the
// other end.
//
// The list above is hand-written, and a hand-written list of variables is the
// shape of thing that falls behind the code reading them — which here is
// silent by construction: the variable simply stops working under sudo, on
// the path most users take, with nothing to report.
//
// So this harvests what the binary actually reads and requires each name to
// be either carried or excused with a reason. Excusing one is a sentence, not
// a deletion.
func TestEveryReadVariableIsCarriedOrExcusedOnPurpose(t *testing.T) {
	for _, name := range readEnvNames(t) {
		if slices.Contains(carriedThroughSudo, name) {
			continue
		}
		if _, ok := notCarried[name]; ok {
			continue
		}
		t.Errorf("cmd/hostveil reads %s but the re-exec does not carry it — under sudo it is "+
			"silently empty. Add it to carriedThroughSudo, or to notCarried with the reason.", name)
	}
	for _, name := range carriedThroughSudo {
		if _, ok := notCarried[name]; ok {
			t.Errorf("%s is both carried and excused", name)
		}
	}
}

// notCarried are the variables read in cmd/hostveil that deliberately do not
// cross the re-exec, each with the reason it must not.
var notCarried = map[string]string{
	"HOSTVEIL_NO_SUDO": "reaching the re-exec at all means this was unset",
	"HOSTVEIL_ELEVATED": "the marker whose non-arrival through sudo is the entire reason " +
		"SUDO_USER is the loop guard; carrying it would re-create the loop it replaced",
	"SUDO_USER":         "sudo sets it in the child itself, which is what makes it the guard",
	"HOSTVEIL_SNAPSHOT": "test-only, and it gates a test that never elevates",
}

// readEnvNames harvests the variable names cmd/hostveil reads.
//
// It walks the package's own source rather than a list kept here, and it
// resolves single-assignment consts, because two of the names are held that
// way (themeEnv, glyphsEnv) — a harvest that only looked at call arguments
// would miss exactly the two variables a user is most likely to set.
func readEnvNames(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	consts := map[string]string{}
	var files []*ast.File

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
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
		t.Fatalf("walk: %v", err)
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
				if s, ok := stringLit(vs.Values[0]); ok {
					consts[vs.Names[0].Name] = s
				}
			}
		}
	}

	var names []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "os" {
				return true
			}
			switch arg := call.Args[0].(type) {
			case *ast.BasicLit:
				if s, ok := stringLit(arg); ok {
					names = append(names, s)
				}
			case *ast.Ident:
				if s, ok := consts[arg.Name]; ok {
					names = append(names, s)
				} else {
					t.Errorf("os.%s is called with %s, which this harvest cannot resolve — "+
						"a variable it cannot see is one nothing checks", sel.Sel.Name, arg.Name)
				}
			}
			return true
		})
	}
	slices.Sort(names)
	names = slices.Compact(names)

	// Nothing-extracted guard. cmd/hostveil reads several; a harvest that
	// stopped matching would pass this test vacuously while the list it
	// checks quietly stopped being checked.
	if len(names) < 5 {
		t.Fatalf("only %d environment reads harvested from cmd/hostveil (%v) — the harvest is "+
			"broken, not the list", len(names), names)
	}
	return names
}

func stringLit(n ast.Node) (string, bool) {
	lit, ok := n.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}
