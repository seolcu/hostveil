package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
)

// fix.Default()'s doc comment is the register of findings deliberately left
// without a fix: each one named, each with the reason it is Manual on
// purpose. TestKnownUnregisteredFindings pins that register from one side —
// it asserts nothing in the list has acquired a fix.
//
// Nothing pinned the other side, and five findings fell through it:
// compose.ds012, compose.dr004, ports.exposed, accounts.uid0 and
// accounts.emptypassword had no registered fix and no entry in the
// register either. That is the state the register exists to make
// impossible. Manual is a decision — "there is no action hostveil can
// safely take" — and a finding that is Manual because nobody has looked at
// it is indistinguishable, in the interface, from one that is Manual
// because a maintainer weighed the remediation and refused it.
//
// So: every finding a checker can emit must either have a fix, or be named
// in the register with a reason. There is no third state.
func TestEveryFindingIsEitherFixableOrDeclinedOnPurpose(t *testing.T) {
	registry := fix.Default()
	declined := declinedInRegister(t)

	for _, id := range emittedFindingIDs(t) {
		if registry.Has(id) {
			continue
		}
		if declined[id] {
			continue
		}
		// A source-wide entry (sysctl.*) covers its whole domain; the
		// register uses one where the reason is genuinely shared.
		if src, _, ok := strings.Cut(id, "."); ok && declined[src+".*"] {
			continue
		}
		t.Errorf("%s has no registered fix and no entry in fix.Default()'s register of "+
			"deliberately-unfixed findings — it is Manual by omission, which a user cannot "+
			"tell from Manual by decision", id)
	}
}

// registerID matches an ID as the register writes it, including the
// source-wide glob form.
var registerID = regexp.MustCompile(`\b(ssh|compose|cve|ports|firewall|accounts|fileperms|updates|agent|sysctl)\.(\*|[a-z0-9][a-z0-9.\-]*)`)

// declinedInRegister reads the doc comment on fix.Default and returns every
// finding ID it names.
//
// It reads the comment rather than a list kept here on purpose: the comment
// is the normative statement — it carries the reasons, and it is what a
// maintainer edits when they change their mind. A copy in a test would be
// one more thing to drift.
func declinedInRegister(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join(repoRoot(t), "internal", "fix", "register.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var doc string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "Default" && fn.Doc != nil {
			doc = fn.Doc.Text()
		}
	}
	if doc == "" {
		t.Fatal("fix.Default has no doc comment — the register of deliberately-unfixed findings is gone")
	}

	out := map[string]bool{}
	for _, m := range registerID.FindAllString(doc, -1) {
		out[m] = true
	}
	// Nothing-extracted guard. The register names well over a dozen
	// findings; a regexp that stopped matching would otherwise make this
	// test demand a fix for every Manual finding in the tree, which reads
	// as a code failure rather than as the test failure it is.
	if len(out) < 10 {
		t.Fatalf("only %d finding IDs extracted from the register (%v) — extraction is broken, not the register",
			len(out), out)
	}
	return out
}
