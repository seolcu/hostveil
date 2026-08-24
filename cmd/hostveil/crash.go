package main

import (
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/diagnostics"
	"github.com/seolcu/hostveil/internal/history"
)

// reportCrash is what a panic that reached run()'s top-level recover becomes:
// a friendly message instead of a bare Go stack trace scrolling off the
// terminal, and a local crash record `hostveil diagnostics` can package up
// afterward.
//
// It never touches the network — see internal/diagnostics's own doc comment
// on why nothing in this path does. Nothing here is allowed to panic itself:
// this already runs from inside a deferred recover, and a second panic from
// the reporting path would print nothing at all instead of the message this
// exists to guarantee.
func reportCrash(args []string, r any, stack []byte) int {
	cmd := "unknown"
	if len(args) > 0 {
		cmd = args[0]
	}
	diagnostics.RecordCrash(history.DefaultDir(), diagnostics.NewRecord(version, cmd, "cli", r, stack))
	fmt.Fprintln(os.Stderr, "hostveil: crashed — this is a bug.")
	// Deliberately not "the host was not changed": unlike the fix-specific
	// crashError in internal/core/contain.go, which only ever fires before
	// a fix's backup-then-write, this is the generic catch-all and can be
	// reached from other places a panic might happen mid-write. Silence on
	// that question is more honest than a guarantee this path cannot back.
	fmt.Fprintln(os.Stderr, "Run `hostveil diagnostics` to package the details for a bug report.")
	return 1
}
