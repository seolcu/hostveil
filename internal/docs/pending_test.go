package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two questions are asked of model.Finding.Fixed and they are not the same
// question. "Is this risk still standing on the host" is Active, because a fix
// that is written and waiting on a restart has changed nothing an attacker can
// see. "Has hostveil already applied a fix here" is Fixed on its own, because
// for that one a pending fix counts.
//
// Every site that asks the first and tests Fixed is a place a pending finding
// silently stops being charged, stops being listed, or stops being emitted —
// and each is invisible until somebody applies a compose fix and reads the
// number. That is the shape of drift internal/docs/afterfixes_test.go was
// written about, one field over: a rule that holds only as long as every
// renderer remembers it.
//
// So the rule is mechanical here instead. Outside internal/model, production
// code does not read .Fixed in a condition; it calls Active or IsAutoFixable.
// The exceptions are the second question, and they are named.
var fixedIsTheRightQuestion = map[string]string{
	"internal/core/batch.go": "the batch skip asks whether hostveil has already applied something here, " +
		"and for a pending fix it has — asking Active would re-apply it on every run until the " +
		"operator restarted the service, writing a checkpoint each time over an unchanged file",
	"internal/core/reportstate.go": "markFixed and unmarkFixed are what set and clear the flag, so they " +
		"are the one place that has to name it",
	"cmd/hostveil/fix.go": "fixAll's eligibility loop asks the batch's question, and it covers the " +
		"Review branch as well as the Auto one, so IsAutoFixable is too narrow for it",
}

// TestNoRendererDecidesForItselfWhetherAPendingFindingCounts reads the source
// rather than the behaviour, for the same reason TestTheOSGateIsWhereItHasTo
// Be does: on a report where nothing has been applied the two predicates agree
// exactly, so every test in this repo that builds its own findings passes
// either way. The disagreement only appears after a real apply, which is the
// one path a unit test does not take.
func TestNoRendererDecidesForItselfWhetherAPendingFindingCounts(t *testing.T) {
	root := repoRoot(t)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			switch {
			case d.Name() == ".git" || d.Name() == "site" || d.Name() == "testdata":
				return fs.SkipDir
			// model owns the predicates, so it is the one package that has to
			// spell the field out.
			case rel == filepath.Join("internal", "model"):
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if _, named := fixedIsTheRightQuestion[filepath.ToSlash(rel)]; named {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", rel, perr)
			return nil
		}
		for _, line := range fixedInACondition(fset, file) {
			t.Errorf("%s reads .Fixed in a condition at line %d.\n"+
				"  Ask model.Finding.Active (is the risk still standing) or IsAutoFixable (would\n"+
				"  the batch apply this) instead. A fix that is applied and not yet in force is\n"+
				"  Fixed and still standing, and testing the field decides which of those this\n"+
				"  site means by accident. If Fixed really is the question here, add the file to\n"+
				"  fixedIsTheRightQuestion with the reason.", rel, line)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// fixedInACondition returns the source lines where a .Fixed selector is read
// rather than assigned to.
//
// Assignment targets are how the flag legitimately gets written — markFixed
// sets it, unmarkFixed and the AfterFixes pass clear it — and a write decides
// nothing. Only the reads pick between the two questions.
func fixedInACondition(fset *token.FileSet, file *ast.File) []int {
	assigned := map[ast.Expr]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range as.Lhs {
				assigned[lhs] = true
			}
		}
		return true
	})
	var lines []int
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Fixed" || assigned[sel] {
			return true
		}
		lines = append(lines, fset.Position(sel.Sel.NamePos).Line)
		return true
	})
	return lines
}

// The dashboard keeps its own copy of the predicate, because it renders in a
// browser and cannot call into Go. That is the copy nothing else can hold to
// the rule, so it is the copy this test reads.
//
// It is the same argument afterfixes_test.go makes about the headroom rule,
// and it applies with more force here: the JS answer decides whether a row the
// score is charging appears on the page at all.
func TestTheDashboardsCopyOfTheActiveRuleMatches(t *testing.T) {
	path := filepath.Join(repoRoot(t), "internal", "ui", "web", "assets", "app.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)

	for _, want := range []struct{ rule, why string }{
		{"!x.fixed || x.pending",
			"active() must keep a pending finding on the page — the score is still charging it, " +
				"and a row that vanished while the number stayed put is a number with nothing behind it"},
		{"!f.fixed && !!(REM[f.remediation]",
			"isAuto() must exclude a pending finding, or the operator can mark a row into a batch " +
				"that reports it back as skipped — the word that also means there is no fix for it"},
	} {
		if !strings.Contains(js, want.rule) {
			t.Errorf("app.js no longer contains %q.\n  %s", want.rule, want.why)
		}
	}
}
