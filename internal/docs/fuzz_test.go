package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The nightly workflow fuzzes each target for five minutes, from a matrix it
// lists by hand. Nothing connects that list to the targets that exist, so a
// Fuzz function added tomorrow is never fuzzed — and the failure is silent in
// the worst way: nightly stays green, the matrix still names four targets, and
// the new parser is the one nobody is throwing bytes at.
//
// This is the same shape as the shellcheck step that named two of thirteen
// scripts, and as the E2E selection that matched no domain: a claim living
// outside Go, where the compiler cannot hold it to anything. So the set is
// derived from the source and compared, in both directions — a target listed
// but absent would fail the nightly run loudly, but it would fail it at 5 AM
// rather than here.
var (
	fuzzMatrixTarget  = regexp.MustCompile(`(?m)^\s*-?\s*target:\s*(\w+)\s*$`)
	fuzzMatrixPackage = regexp.MustCompile(`(?m)^\s*-?\s*package:\s*(\S+)\s*$`)
)

// fuzzTargets walks the repository for Fuzz functions, returning each target
// name against the package path it lives in.
//
// Extracted so more than one thing can be held to the real list. It was inline
// in the test below, which is why AGENTS.md was free to name three of the five
// — the workflow was pinned and the prose beside it was not.
func fuzzTargets(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	found := map[string]string{} // target -> ./package/path

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "site" || name == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return nil // not this test's job to report unparseable Go
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
				continue
			}
			if !isFuzzTarget(fn) {
				continue
			}
			rel, rerr := filepath.Rel(root, filepath.Dir(path))
			if rerr != nil {
				return rerr
			}
			found[fn.Name.Name] = "./" + filepath.ToSlash(rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("found no Fuzz targets in the repository, which cannot be right — " +
			"the walk or the signature check above stopped working, and every test " +
			"built on this list would now pass on anything")
	}
	return found
}

func TestEveryFuzzTargetIsFuzzedNightly(t *testing.T) {
	found := fuzzTargets(t)

	wf := readRepoFile(t, filepath.Join(".github", "workflows", "nightly.yml"))
	targets := captured(fuzzMatrixTarget, wf)
	packages := captured(fuzzMatrixPackage, wf)
	if len(targets) == 0 {
		t.Fatal("nightly.yml lists no fuzz targets; either the matrix moved or " +
			"its markup changed, and this pin is testing nothing")
	}
	if len(targets) != len(packages) {
		t.Fatalf("nightly.yml pairs %d targets with %d packages; the matrix rows "+
			"no longer line up", len(targets), len(packages))
	}

	listed := map[string]string{}
	for i, name := range targets {
		listed[name] = packages[i]
	}

	for name, pkg := range found {
		got, ok := listed[name]
		if !ok {
			t.Errorf("%s is a fuzz target in %s and nightly.yml does not fuzz it; "+
				"add it to the matrix in .github/workflows/nightly.yml", name, pkg)
			continue
		}
		if got != pkg {
			t.Errorf("nightly.yml fuzzes %s in %s, but it is declared in %s",
				name, got, pkg)
		}
	}
	for name := range listed {
		if _, ok := found[name]; !ok {
			t.Errorf("nightly.yml fuzzes %s, which no longer exists; "+
				"`go test -fuzz` would fail the nightly run", name)
		}
	}
}

// isFuzzTarget reports whether fn has the one signature `go test -fuzz` will
// accept: a single *testing.F parameter and no results. Without this a helper
// named FuzzSomethingHelper would be demanded of the workflow, and the error
// would be about a workflow rather than about the helper's name.
func isFuzzTarget(fn *ast.FuncDecl) bool {
	if fn.Type.Results != nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing" && sel.Sel.Name == "F"
}

func captured(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// A crash corpus is only worth uploading if it is uploaded from the job that
// produced it, so the matrix has to keep running every target after one of
// them fails. fail-fast defaults to true.
func TestOneFailingFuzzTargetDoesNotCancelTheOthers(t *testing.T) {
	wf := readRepoFile(t, filepath.Join(".github", "workflows", "nightly.yml"))
	if !strings.Contains(wf, "fail-fast: false") {
		t.Error("nightly.yml's fuzz matrix no longer sets fail-fast: false, so the " +
			"first target to crash cancels the rest and their corpora are never uploaded")
	}
}

// TestAgentsMdNamesEveryFuzzTarget.
//
// The line above the nightly matrix in AGENTS.md tells an agent which targets
// exist, and it named three of the five. FuzzUnified and FuzzJSON5Edit were
// fuzzed nightly and invisible to anyone reading the file that is supposed to
// be the orientation — TestEveryFuzzTargetIsFuzzedNightly pins the workflow
// against the source and nothing pinned the sentence beside it.
//
// It is the same shape as the drift AGENTS.md's own header warns about: "a
// workflow is YAML, so nothing in it can be held to the code by a compiler".
// A comment is not YAML and cannot be either.
func TestAgentsMdNamesEveryFuzzTarget(t *testing.T) {
	agents := readRepoFile(t, "AGENTS.md")
	for name := range fuzzTargets(t) {
		if !strings.Contains(agents, name) {
			t.Errorf("AGENTS.md does not name the fuzz target %s.\n"+
				"  It is the list an agent reads to know what exists, and a short list reads "+
				"exactly like a complete one.", name)
		}
	}
}
