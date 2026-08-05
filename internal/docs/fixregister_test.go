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
var registerID = regexp.MustCompile(`\b(ssh|compose|cve|ports|firewall|accounts|fileperms|updates|agent|sysctl|dockerd|systemd)\.(\*|[a-z0-9][a-z0-9.\-]*)`)

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

// unfixableInDocs reads the checks table and returns every finding the docs
// say a user is shown with no fix to apply.
//
// The checks table is the right source and the register is not. The register
// names findings it *argues about*, which includes ones held up as
// counter-examples — cve.outdated-image is in it precisely because it is the
// one CVE finding that does have a fix, and agent.config-perms is in it as an
// Auto fix that touches a home directory. Demanding a decline reason for
// those would be demanding an explanation for something that never happens.
//
// The table's Fix column is already pinned against the registry by
// cmd/sitegen's TestDocumentedFixKindsMatchTheRegistry, so reading it here is
// reading the registry through a check that fails if the two ever disagree.
func unfixableInDocs(t *testing.T) map[string]bool {
	t.Helper()
	page := readRepoFile(t, filepath.Join("cmd", "sitegen", "content", "en", "docs", "checks.html"))
	rows := regexp.MustCompile(`<tr><td><code>([a-z0-9.\-]+)</code></td>.*?<td>([^<]*)</td></tr>`).
		FindAllStringSubmatch(page, -1)
	if len(rows) == 0 {
		t.Fatal("no finding rows parsed from the checks page; the table markup changed")
	}
	out := map[string]bool{}
	for _, r := range rows {
		if r[2] == "Manual" || r[2] == "Unavailable" {
			out[r[1]] = true
		}
	}
	if len(out) < 20 {
		t.Fatalf("only %d unfixable findings parsed from the checks table — extraction is broken, "+
			"not the table", len(out))
	}
	return out
}

// TestEveryDeclinedFindingSaysWhy is the side of the register that faces the
// user.
//
// TestKnownUnregisteredFindings asserts nothing in the register has acquired
// a fix. TestEveryFindingIsEitherFixableOrDeclinedOnPurpose asserts nothing
// is Manual by omission. Both are about the maintainer's view. Neither says
// anything about the user's, and the user is the one looking at a finding
// with no button on it.
//
// The reasons were always written down — the register is pages of them — in a
// doc comment nobody outside this repository will ever read. fix.WhyNoFix is
// the same decision reaching the finding it is about, and this is what keeps
// the two from parting.
func TestEveryDeclinedFindingSaysWhy(t *testing.T) {
	unfixable := unfixableInDocs(t)

	for id := range unfixable {
		if fix.WhyNoFix(id) == "" {
			t.Errorf("%s reaches a user with no fix and fix.WhyNoFix has nothing to say about it — "+
				"they see a finding with no button and no reason", id)
		}
	}

	// And the other way: a reason for a finding that does have a fix would
	// never be shown, so it is dead text nobody would notice going stale.
	declined := declinedInRegister(t)
	for _, id := range fix.DeclinedIDs() {
		if strings.HasSuffix(id, ".*") {
			// A domain-wide entry is legitimate exactly where the register
			// argues at that level (systemd.*, dockerd.*).
			if !declined[id] {
				t.Errorf("fix.WhyNoFix has a domain-wide entry %s that the register does not "+
					"argue for as a domain", id)
			}
			continue
		}
		if !unfixable[id] {
			t.Errorf("fix.WhyNoFix explains %s, which the checks table says a user can fix — "+
				"the reason would never be shown", id)
		}
	}
}

// A reason that restates the finding is not a reason, and one that runs on is
// not readable in a detail pane a few dozen columns wide. Neither is
// checkable in general; these are the mechanical parts of it.
func TestDeclineReasonsAreOneShortSentence(t *testing.T) {
	const maxLen = 200
	for _, id := range fix.DeclinedIDs() {
		r := fix.WhyNoFix(id)
		switch {
		case r == "":
			t.Errorf("%s is listed as declined with an empty reason", id)
		case len(r) > maxLen:
			t.Errorf("%s: reason is %d characters, over the %d-character budget:\n  %s", id, len(r), maxLen, r)
		case strings.Count(r, ". ") > 1:
			t.Errorf("%s: reason runs to %d sentences; one is the budget:\n  %s",
				id, strings.Count(r, ". ")+1, r)
		}
	}
}
