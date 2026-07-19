package web

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUIStaysThin enforces that production web code goes through core and
// never reaches into fix/history/check/compose directly — the same
// structural boundary the TUI has. (Test files may wire fixtures.)
func TestUIStaysThin(t *testing.T) {
	forbidden := []string{"internal/fix", "internal/history", "internal/check", "internal/compose"}

	for _, path := range productionGoFiles(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.Contains(p, bad) {
					t.Errorf("%s imports forbidden package %q — web UI must go through core", path, p)
				}
			}
		}
	}
}

// productionGoFiles lists the non-test .go files in this directory. Reading
// the directory directly rather than via the deprecated parser.ParseDir:
// this check only cares about import lines, so package grouping and build
// tags are irrelevant.
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
