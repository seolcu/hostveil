package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// evidenceRead matches a fix reading a key off a finding: f.Evidence["port"].
var evidenceRead = regexp.MustCompile(`Evidence\["([a-zA-Z0-9_-]+)"\]`)

// Evidence is the one string contract in this repository that nothing was
// holding together.
//
// Finding IDs have five tests, environment variables three, the model's enums
// two, the layout registries two, the severity CSS two. Evidence — the keys a
// checker writes and a fix parses to build a remediation out of — had none, in
// either direction.
//
// The direction that matters is a fix reading a key no checker writes. It does
// not fail loudly: the builder returns an error, Engine.classify demotes the
// finding to Manual, and the user is left with a finding whose fix button
// vanished and no explanation anywhere. Two keys are deliberately conditional
// and are listed below with the reason.
func TestEveryEvidenceKeyAFixReadsIsWrittenByAChecker(t *testing.T) {
	root := repoRoot(t)
	written := evidenceKeysWritten(t, filepath.Join(root, "internal", "check"))
	read := evidenceKeysRead(t, filepath.Join(root, "internal", "fix"))

	if len(read) == 0 || len(written) == 0 {
		t.Fatalf("harvested %d read and %d written keys; the patterns have stopped matching",
			len(read), len(written))
	}

	for key := range read {
		if !written[key] {
			t.Errorf("internal/fix reads Evidence[%q] and no checker writes it — "+
				"the builder errors, classify demotes the finding to Manual, and the "+
				"user sees a fix button disappear with nothing to say why", key)
		}
	}
}

// conditionalKeys are written only in some circumstances, and each fix that
// reads one says what it does when it is absent. They are named here so the
// list of what is deliberately optional is written down somewhere rather than
// being rediscovered from a nil map.
var conditionalKeys = map[string]string{
	"ssh_port": "firewall.inactive carries it only where `ss` could be read; without it the fix errors rather than enabling a firewall on an unknown port",
	"set-by":   "sysctl carries it only where an origin file was found; its absence means the kernel default, which the fix handles",
	"set-alt":  "the agent config fixes carry it only where a key has two safe values; its absence is what makes the fix Auto rather than Review",
}

// And the reverse, weakly: a key nothing reads is not a defect, because
// evidence is also rendered to the user and exported in --json. What this
// asserts is only that the conditional list above has not gone stale.
func TestTheConditionalEvidenceKeysAreStillConditional(t *testing.T) {
	root := repoRoot(t)
	read := evidenceKeysRead(t, filepath.Join(root, "internal", "fix"))
	for key := range conditionalKeys {
		if !read[key] {
			t.Errorf("%q is documented as a conditional evidence key and no fix reads it any more", key)
		}
	}
}

func evidenceKeysRead(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	walkGo(t, dir, func(path string, src string) {
		for _, m := range evidenceRead.FindAllStringSubmatch(src, -1) {
			out[m[1]] = true
		}
	})
	return out
}

// evidenceKeysWritten collects the first argument of every WithEvidence call
// under the checkers, through the AST so a key built by a helper is visible as
// the constant it is rather than as a line of text.
func evidenceKeysWritten(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	walkGoFiles(t, dir, func(path string, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "WithEvidence" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					out[s] = true
				}
			}
			return true
		})
	})
	// Not every write goes through WithEvidence: a checker that decides a key
	// after building the finding assigns into the map directly
	// (`f.Evidence["installed"] = "true"`). Those are picked up textually,
	// which cannot tell a write from a read — but on the checker side there
	// is nothing to read, so every match is a write.
	walkGo(t, dir, func(_ string, src string) {
		for _, m := range evidenceRead.FindAllStringSubmatch(src, -1) {
			out[m[1]] = true
		}
	})
	return out
}

func walkGo(t *testing.T, dir string, fn func(path, src string)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		fn(path, readRepoFile(t, mustRel(t, path)))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

func walkGoFiles(t *testing.T, dir string, fn func(path string, file *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		fn(path, file)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

func mustRel(t *testing.T, path string) string {
	t.Helper()
	rel, err := filepath.Rel(repoRoot(t), path)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}
