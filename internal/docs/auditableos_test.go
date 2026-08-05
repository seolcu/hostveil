package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"testing"
)

// osGated are the checkers whose Available must consult platform.AuditableOS,
// and the reason each one has to.
//
// The other nine do not need it: they probe something a non-Linux host
// genuinely lacks — /proc/sys, systemd, apt-get, ss, a reachable Docker
// daemon — and skip cleanly on their own. These three probe something that
// exists on macOS and means something else there, so without the gate each
// produces an answer about a host it never examined.
var osGated = map[string]string{
	"firewall": "probes only ufw, firewall-cmd, nft and iptables; on a host with none of them " +
		"nothing fails, and the absence of a failure was read as the absence of a firewall — a " +
		"top-severity finding on every Mac, whose packet filter is pf",
	"accounts": "/etc/passwd exists on macOS as a stub (the account database is Open Directory), " +
		"so the UID-0 scan passes against something that does not describe the host, and the " +
		"missing /etc/shadow produces advice to re-run with sudo that cannot ever help",
	"agent": "enumerates homes out of that same /etc/passwd keeping uid 0 and 1000..65533; macOS " +
		"accounts start at 501, so it finds only /var/root and reports 'no agent runtime' about a " +
		"host whose /Users it never opened",
}

// TestTheOSGateIsWhereItHasToBe pins which checkers consult platform.Auditable
// OS from their Available.
//
// A checker dropping the call is silent on Linux — every test here runs on
// Linux, CI cross-compiles darwin but never executes it, and the demo VM is
// Ubuntu. The failure only appears on a user's Mac, as a finding about
// something hostveil did not look at, which is the one thing this codebase
// says a checker must never produce.
//
// It reads the source rather than calling Available, because on this platform
// the gate returns true and a checker that had stopped calling it would
// behave identically.
func TestTheOSGateIsWhereItHasToBe(t *testing.T) {
	for domain := range osGated {
		path := filepath.Join(repoRoot(t), "internal", "check", domain, domain+".go")
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			continue
		}
		if !availableCallsAuditableOS(file) {
			t.Errorf("internal/check/%s's Available does not consult platform.AuditableOS — %s",
				domain, osGated[domain])
		}
	}
}

// And the other direction: a checker that grew the gate without a recorded
// reason. The gate makes a domain report nothing at all on a platform, which
// is a large thing to do quietly.
func TestNoCheckerIsOSGatedWithoutAReason(t *testing.T) {
	for _, domain := range checkDomains(t) {
		if _, listed := osGated[domain]; listed {
			continue
		}
		path := filepath.Join(repoRoot(t), "internal", "check", domain, domain+".go")
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			continue // a domain whose entry point is named differently; the test above covers the gated three
		}
		if availableCallsAuditableOS(file) {
			t.Errorf("internal/check/%s is OS-gated but osGated has no entry saying why — the gate "+
				"silences a whole domain on a platform, which needs a sentence", domain)
		}
	}
}

// checkDomains lists the packages under internal/check that look like a
// detection domain: a directory whose name matches a file inside it.
func checkDomains(t *testing.T) []string {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(repoRoot(t), "internal", "check", "*", "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	seen := map[string]bool{}
	for _, p := range entries {
		dir := filepath.Base(filepath.Dir(p))
		if filepath.Base(p) == dir+".go" {
			seen[dir] = true
		}
	}
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	if len(out) < 10 {
		t.Fatalf("only %d detection domains found (%v) — the discovery is broken, not the tree",
			len(out), out)
	}
	return out
}

func availableCallsAuditableOS(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Available" || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "AuditableOS" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "platform" {
				found = true
			}
			return true
		})
		return false
	})
	return found
}
