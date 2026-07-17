package web

import (
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestUIStaysThin enforces that production web code goes through core and
// never reaches into fix/history/check/compose directly — the same
// structural boundary the TUI has. (Test files may wire fixtures.)
func TestUIStaysThin(t *testing.T) {
	forbidden := []string{"internal/fix", "internal/history", "internal/check", "internal/compose"}

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
						t.Errorf("%s imports forbidden package %q — web UI must go through core", path, p)
					}
				}
			}
		}
	}
}
