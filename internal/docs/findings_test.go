package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The docs table in content/{en,ko}/docs/checks.html is the enumeration of
// every finding hostveil can report, and cmd/sitegen's TestDocumentedFixKinds
// MatchTheRegistry already pins each documented row against the fix registry.
// But it iterates the *documented* rows, so it can only check findings the
// table already lists. A checker that starts emitting a new ID and nobody
// adds a row stays invisible to every guard in the repo: the docs test never
// looks at it, the fix registry never has to declare a position on it, and
// the finding ships undocumented with whatever remediation the checker
// happened to declare.
//
// This test closes that loop from the other end — it harvests the IDs the
// checkers actually construct and requires each to be documented. Together
// the two make the chain complete: emitted → documented → registry position.

// findingID matches a namespaced finding ID. The namespace must be one of
// the real sources, so incidental dotted strings in the check packages
// (config filenames, config keys like net.bindIp) do not masquerade as IDs.
var findingID = regexp.MustCompile(`^(ssh|compose|cve|ports|firewall|accounts|fileperms|updates|agent)\.[a-z0-9][a-z0-9.\-]*$`)

// composeRuleID matches compose's bare rule IDs, which reach NewFinding
// through a helper that prefixes them: f("ds016", …) → "compose.ds016".
var composeRuleID = regexp.MustCompile(`^(ds|dr)\d+$`)

// emittedFindingIDs walks internal/check and collects every finding ID the
// checkers can construct from a string literal.
func emittedFindingIDs(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(repoRoot(t), "internal", "check")
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		isCompose := file.Name.Name == "compose"

		// Any namespaced string literal counts, wherever it sits. Keying off
		// an argument position was tried and was wrong: IDs reach the
		// constructor as arg 0 (model.NewFinding), as arg 1 (ports'
		// exposedFinding helper), through a local (agent's id, title, desc
		// := …), and through a table field (agent's danger rules). The
		// namespace prefix is what actually identifies a finding ID, and
		// over-collecting only ever demands a doc row for something that
		// looks like a finding — the safe direction to err in.
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := stringLit(n)
			if !ok {
				return true
			}
			switch {
			case findingID.MatchString(lit):
				seen[lit] = true
			case isCompose && composeRuleID.MatchString(lit):
				seen["compose."+lit] = true // f("ds016", …) → compose.ds016
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/check: %v", err)
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func stringLit(n ast.Node) (string, bool) {
	lit, ok := n.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// documentedFindingIDs reads the IDs listed in the English checks page. The
// two languages are already pinned against each other by
// TestBothLanguagesDocumentTheSameFindings, so one is enough here.
func documentedFindingIDs(t *testing.T) []string {
	t.Helper()
	page := readRepoFile(t, filepath.Join("cmd", "sitegen", "content", "en", "docs", "checks.html"))
	rows := regexp.MustCompile(`<tr><td><code>([a-z0-9.\-]+)</code></td>`).FindAllStringSubmatch(page, -1)
	if len(rows) == 0 {
		t.Fatal("no finding rows parsed from the checks page; the table markup changed")
	}
	var ids []string
	for _, r := range rows {
		ids = append(ids, r[1])
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// TestEveryEmittedFindingIsDocumented is the guard the repo was missing: a
// finding a checker can report but the table does not list.
func TestEveryEmittedFindingIsDocumented(t *testing.T) {
	documented := documentedFindingIDs(t)
	for _, id := range emittedFindingIDs(t) {
		if !slices.Contains(documented, id) {
			t.Errorf("checkers can emit %s but cmd/sitegen/content/{en,ko}/docs/checks.html does not "+
				"list it — an undocumented finding also escapes the docs-vs-fix-registry check", id)
		}
	}
}

// TestDocumentedFindingsAreStillEmitted is the same guard pointing the other
// way: a row for a finding no checker constructs any more is a promise the
// tool no longer keeps. It is a softer failure than the reverse, so it names
// the retired ID rather than guessing whether the row or the checker is
// wrong. It also keeps the harvest itself honest: the two tests together
// assert set equality, so a checker that starts building IDs in a shape the
// walk cannot see fails here rather than silently shrinking coverage.
func TestDocumentedFindingsAreStillEmitted(t *testing.T) {
	emitted := emittedFindingIDs(t)
	for _, id := range documentedFindingIDs(t) {
		if !slices.Contains(emitted, id) {
			t.Errorf("the checks table documents %s but no checker constructs it — "+
				"either the row is stale or the ID was renamed", id)
		}
	}
}
