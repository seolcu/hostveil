package history

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This package is the recovery layer: the checkpoints it holds are the only
// copy of what a fix overwrote, and the scan snapshots it holds are the
// baseline every delta is computed against. Both are files that something
// else depends on being whole, and os.WriteFile truncates the target before
// it writes a byte — so a crash, an OOM kill, or delayed allocation on XFS
// or btrfs leaves a valid-looking file that is a prefix of the real one.
//
// AGENTS.md states the rule as "every write in internal/history goes
// through platform.WriteFileAtomic". It was not quite true: SaveReport
// still used os.WriteFile, which is how the newest scan snapshot — the one
// LastReport reads and the next scan diffs against — could be torn.
//
// A test that provokes a torn write would have to crash the process at a
// chosen instant, which is not something a unit test can do reliably. So
// this asserts the property the invariant is actually about: no production
// file here calls os.WriteFile at all. It is the same shape as the UI
// layering tests — read the source, fail on the call that must not exist.
func TestNoProductionWriteBypassesAtomicWrite(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
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
			if !ok || pkg.Name != "os" {
				return true
			}
			// os.Remove and os.ReadFile are fine — the rule is about
			// creating or replacing a file's contents, which is the only
			// operation that can leave a truncated one behind.
			if sel.Sel.Name == "WriteFile" || sel.Sel.Name == "Create" {
				t.Errorf("%s calls os.%s; every write in this package must go through platform.WriteFileAtomic",
					name, sel.Sel.Name)
			}
			return true
		})
	}
	// Nothing-extracted guard: a glob that matched no production file would
	// pass this test while checking nothing.
	if checked < 2 {
		t.Fatalf("only %d production files scanned — the package layout moved and this test did not", checked)
	}
}

// A scan snapshot has to survive the round trip byte for byte: the delta is
// computed by unmarshalling it, so a write that changed the content at all
// would be a wrong delta rather than a missing one.
func TestSaveReportRoundTrips(t *testing.T) {
	s := NewStore(t.TempDir())
	want := []byte(`{"findings":[],"score":{"overall":42}}`)
	if err := s.SaveReport(NewScanID(), want); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.LastReport()
	if err != nil || !ok {
		t.Fatalf("LastReport() = ok %v, err %v", ok, err)
	}
	if string(got) != string(want) {
		t.Errorf("round-tripped %q, want %q", got, want)
	}

	// The atomic write stages beside the target and renames. If a temp file
	// were left behind, scanFiles would sort it in as though it were a
	// snapshot and LastReport could return it.
	entries, err := os.ReadDir(filepath.Join(s.dir, "scans"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("scans dir holds %v, want exactly one snapshot", names)
	}
}
