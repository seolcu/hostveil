package tui

import (
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestUIStaysThin enforces the architectural boundary that keeps the UI a
// thin shell: production TUI code may import only the engine (core) and
// value types (model), never the fix, history, check, or compose packages
// directly. Reaching into those is exactly how hostveil v2 ended up with
// fix logic duplicated across its UIs. (Test files are exempt — they may
// wire fixtures.)
func TestUIStaysThin(t *testing.T) {
	forbidden := []string{
		"internal/fix",
		"internal/history",
		"internal/check",
		"internal/compose",
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range forbidden {
					if strings.Contains(p, bad) {
						t.Errorf("%s imports forbidden package %q — UI must go through core", path, p)
					}
				}
			}
		}
	}
}
