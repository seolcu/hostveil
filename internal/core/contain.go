package core

import (
	"fmt"
	"runtime/debug"

	"github.com/seolcu/hostveil/internal/diagnostics"
	"github.com/seolcu/hostveil/internal/fix"
)

// A crash inside a fix ends that fix, not the process.
//
// internal/check.runOne has said since the beginning that a panic in one
// checker degrades only that domain. The fix path said nothing, and it takes
// more with it when it goes: `serve` runs as root and an unrecovered panic
// ends the process for every request in flight, `fix --all` loses every fix it
// had not reached along with the operator's chance to read what did land, and
// a TUI session dies mid-preview with the terminal still in the alternate
// screen.
//
// The exposure is not theoretical. A fix builder reads the host to decide
// which file to edit, and a Transform is the one place in this program where
// host-supplied bytes meet a hand-written parser: compose YAML surgery, JSON5
// editing, sshd_config rewriting. Two of those already carry fuzz targets,
// which is an admission that hostile input reaches them. And a Transform sees
// bytes read at apply time, not at scan time, so they can differ from the ones
// a checker parsed successfully minutes earlier.
//
// Turning the panic into an ordinary error puts a crashing fix on the same
// footing as one that could not build, which every caller already handles: the
// single-fix paths surface the message, and a batch records it under Failed
// and carries on to the next finding.
//
// The stack goes into the error, and now also into a diagnostics.CrashRecord
// under the engine's state directory. There is no log all three interfaces
// read, and a panic in a fix is a bug report hostveil wants back — the error
// message keeps the trace visible right where the fix failed, and the record
// is what lets `hostveil diagnostics` find it again afterward without the
// operator having had to copy it out of a scrolled-away terminal.
func (e *Engine) crashError(what, id string, r any) error {
	stack := debug.Stack()
	diagnostics.RecordCrash(e.store.Dir(), diagnostics.NewRecord(e.version, "fix", "fix "+id, r, stack))
	return fmt.Errorf("the fix for %s crashed while %s: %v\n\n"+
		"This is a bug in Hostveil and the host was not changed. "+
		"Please report it with the trace below.\n\n%s", id, what, r, stack)
}

// safeTransform runs an edit action's transform with a crash contained.
//
// It returns no bytes on a crash, which is what keeps a half-built result away
// from the writer: a transform that panicked partway has said nothing about
// what the file should contain, and the named return would otherwise carry
// whatever it had assembled so far.
func (e *Engine) safeTransform(a fix.Action, id string, in []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, e.crashError("rewriting "+a.Path, id, r)
		}
	}()
	return a.Transform(in)
}
