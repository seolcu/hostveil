package docs

import (
	"go/ast"
	"path/filepath"
	"strings"
	"testing"
)

// mutatingCalls are the ways a package could change the host. A checker that
// used any of them would break the rule the whole design rests on.
var mutatingCalls = map[string][]string{
	"os":   {"WriteFile", "Remove", "RemoveAll", "Create", "Chmod", "Chown", "Mkdir", "MkdirAll", "Rename", "Truncate", "Symlink", "Link"},
	"exec": {"Command", "CommandContext"},
}

// "Checkers are strictly read-only" is true today and nothing enforces it.
//
// It is the reason a scan is safe to run on somebody else's production server
// without asking, the reason `Engine.Scan` can share one command cache across
// twelve of them, and the reason a panic in one degrades a domain rather than
// leaving a host half-edited. All of that rests on a property no test held.
//
// internal/history/atomicity_test.go does exactly this job for the recovery
// layer, reading its own package's sources and failing on a write that
// bypasses the atomic helper. This is the same shape for the other end.
func TestNoCheckerMutatesTheHost(t *testing.T) {
	root := repoRoot(t)
	checked := 0

	walkGoFiles(t, filepath.Join(root, "internal", "check"), func(path string, file *ast.File) {
		// checktest builds hosts for tests to scan; it is scaffolding, not a
		// checker, and it writes fixtures on purpose.
		if strings.Contains(path, filepath.Join("check", "checktest")) {
			return
		}
		checked++
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			for _, name := range mutatingCalls[pkg.Name] {
				if sel.Sel.Name == name {
					t.Errorf("%s calls %s.%s — checkers are read-only, and everything from the "+
						"shared scan cache to running a scan on somebody's production host rests on it",
						rel, pkg.Name, name)
				}
			}
			return true
		})
	})

	if checked < 12 {
		t.Fatalf("only %d checker files were examined; this check would pass vacuously", checked)
	}
}
