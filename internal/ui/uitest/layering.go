package uitest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Forbidden are the packages a UI may not import.
//
// It is a variable rather than a literal in each caller because it was a
// literal in each caller: the same four strings were written out in
// internal/ui/tui and internal/ui/web, and adding a fifth to one of them
// would have left the other half of the boundary open with nothing to say
// so. The boundary is what stopped v2's fix logic from being duplicated
// across the interfaces, so half of it enforced is the failure it exists to
// prevent, arriving through its own guard.
//
// UIs may import core and model. Everything below is reachable only through
// the engine.
var Forbidden = []string{
	"internal/fix",
	"internal/history",
	"internal/check",
	"internal/compose",
}

// AssertThinUI fails if any production file in the calling package's
// directory imports something a UI may not.
//
// It reads "." rather than taking a path, so each UI package calls it from
// its own directory and cannot accidentally check the other one — which
// would pass while testing nothing.
//
// Test files are exempt: they may wire fixtures, and this file being in a
// package the UIs import only from tests is the same allowance.
func AssertThinUI(t *testing.T) {
	t.Helper()

	for _, path := range productionGoFiles(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range Forbidden {
				if strings.Contains(p, bad) {
					t.Errorf("%s imports forbidden package %q — a UI must go through core", path, p)
				}
			}
		}
	}
}

// productionGoFiles lists the non-test .go files in the working directory.
// Reading the directory directly rather than via the deprecated
// parser.ParseDir: this check only cares about import lines, so package
// grouping and build tags are irrelevant.
func productionGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(".", name))
	}
	if len(out) == 0 {
		t.Fatal("no production Go files found — the layering check would pass vacuously")
	}
	return out
}
