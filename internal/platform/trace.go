package platform

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// TraceRunner wraps a CommandRunner and writes a line per command to w.
//
// It exists because hostveil had no way at all to answer the commonest
// support question there is: "it says my firewall is inactive, but it
// isn't." Every claim the tool makes about a host comes from a command run
// through this interface, so a log of what was run and what came back is
// the whole diagnosis — and without it the only evidence was a domain's
// Reason string, which collapses stderr to one line and truncates it to 200
// runes.
//
// What it deliberately does not record is stdout. `docker inspect` alone
// reaches megabytes, and the output frequently contains environment
// variables — a trace an operator pastes into a bug report must not be a
// credential leak. The command, how long it took, and whether it failed are
// what identify the problem; the parse of a successful command is a
// different kind of bug.
type TraceRunner struct {
	inner CommandRunner
	mu    sync.Mutex // one whole line at a time; checkers run concurrently
	w     io.Writer
}

// NewTraceRunner wraps r so every command is logged to w.
func NewTraceRunner(r CommandRunner, w io.Writer) *TraceRunner {
	return &TraceRunner{inner: r, w: w}
}

// Run executes the command and logs it with its duration and outcome.
func (t *TraceRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	start := time.Now()
	out, err := t.inner.Run(ctx, name, args...)
	t.logf("run  %s (%s) %s", quoteArgv(name, args), time.Since(start).Round(time.Millisecond), outcome(err, len(out)))
	return out, err
}

// LookPath resolves a binary and logs whether it was found. This is half of
// every "checker skipped my domain" report: Available gates on it, and a
// binary in /usr/sbin that is not on a non-login PATH looks exactly like a
// binary that is not installed.
func (t *TraceRunner) LookPath(name string) (string, error) {
	path, err := t.inner.LookPath(name)
	if err != nil {
		t.logf("look %s → not found", name)
	} else {
		t.logf("look %s → %s", name, path)
	}
	return path, err
}

func (t *TraceRunner) logf(format string, a ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.w, "hostveil[trace] "+format+"\n", a...)
}

func outcome(err error, n int) string {
	if err != nil {
		return "FAILED: " + err.Error()
	}
	return fmt.Sprintf("ok, %d bytes", n)
}

// quoteArgv renders a command the way a person would retype it, quoting only
// the arguments that need it. A trace whose commands cannot be copied back
// into a shell is half a diagnostic.
func quoteArgv(name string, args []string) string {
	var b strings.Builder
	b.WriteString(shellQuote(name))
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(shellQuote(a))
	}
	return b.String()
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`|&;<>()*?[]{}!#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
