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

// leakedSelector matches a Go selector expression sitting in prose: a
// single-letter receiver, a dot, and a field name.
//
// Single-letter because that is what this codebase's receivers and locals are
// — t, s, c, f, p, r — and requiring at least three characters after the dot
// is what keeps "e.g." and "i.e." out. Real prose in these packages does
// contain dotted names (tools.exec.security, docker.sock, dnf-automatic.timer,
// 127.0.0.1), and none of them has a word boundary before a lone letter, so
// the pattern does not see them.
var leakedSelector = regexp.MustCompile(`\b[a-z]\.[a-z][A-Za-z0-9_]{2,}\b`)

// proseRoots are the packages whose string literals are read by a person: the
// checkers' titles, descriptions and how-to-fix text, the fixes' labels and
// warnings, and the model's own wording.
var proseRoots = []string{
	filepath.Join("internal", "check"),
	filepath.Join("internal", "fix"),
	filepath.Join("internal", "model"),
}

// TestNoFindingProseCarriesAGoIdentifier is the test that was missing when a
// refactor rewrote prose.
//
// #702 threaded a struct through five signatures with a regular expression
// that replaced identifiers — and it replaced them inside string literals as
// well, so every CVE finding on every host read "The t.image nginx:1.21 ships
// 12 vulnerabilities…" in the CLI, the terminal, the dashboard, --json and
// SARIF. The full gate passed. The pinned terminal frame and the pixel
// comparison of the dashboard both passed too, because both draw a fixture
// and neither renders what a checker writes.
//
// Twelve domains' worth of sentences are half of what this product is, and
// nothing read them. This reads them.
func TestNoFindingProseCarriesAGoIdentifier(t *testing.T) {
	root := repoRoot(t)
	checked := 0

	for _, rel := range proseRoots {
		dir := filepath.Join(root, rel)
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Errorf("parse %s: %v", path, perr)
				return nil
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				// Unquote handles raw strings, so a backtick literal that
				// happens to contain a quote is one literal rather than a
				// span running into the next one.
				text, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				checked++
				for _, m := range leakedSelector.FindAllString(text, -1) {
					pos := fset.Position(lit.Pos())
					relPath, _ := filepath.Rel(root, pos.Filename)
					t.Errorf("%s:%d has %q inside a string — a Go identifier reached prose a user reads:\n  %s",
						relPath, pos.Line, m, text)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", rel, err)
		}
	}

	if checked == 0 {
		t.Fatal("no string literals were examined; this check would pass vacuously")
	}
}

// And the pattern has to actually match the thing it was written for. A
// regular expression nobody has seen fail is a regular expression nobody
// knows the behaviour of — this file's own subject.
func TestTheLeakedSelectorPatternMatchesWhatItWasWrittenFor(t *testing.T) {
	broken := []string{
		"Re-pull the t.image and recreate the service: `docker compose -f %s pull %s`",
		"This t.service pins its t.image by digest, so pulling cannot change it.",
		"The t.image %s ships %d vulnerabilit%s that are already fixed upstream (%s).",
		"whether a differently-based t.image would carry less risk",
	}
	for _, s := range broken {
		if !leakedSelector.MatchString(s) {
			t.Errorf("the pattern does not catch the regression it exists for: %q", s)
		}
	}

	// Real sentences from these packages that must not trip it.
	fine := []string{
		"Set `tools.exec.security` to `deny` (or `ask`) and `tools.exec.ask` to `always`.",
		"Mounting /var/run/docker.sock gives the container full control of the Docker daemon.",
		"Bind the published port to 127.0.0.1 so only this host can connect.",
		"`dnf install dnf-automatic` then `systemctl enable --now dnf-automatic.timer`",
		"An .env file is world-readable",
		"e.g. `chmod 0640 /etc/shadow`",
		"Set PermitRootLogin prohibit-password after confirming a key-based login works.",
	}
	for _, s := range fine {
		if m := leakedSelector.FindString(s); m != "" {
			t.Errorf("the pattern reads %q as a leaked identifier in ordinary prose: %q", m, s)
		}
	}
}
