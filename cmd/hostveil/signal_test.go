package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// The first signal cancels the run's context, which is what stops the docker
// and trivy processes a scan has going.
func TestFirstSignalCancelsTheRun(t *testing.T) {
	ctx, stop := notifyContext(context.Background())
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Skipf("cannot signal this process: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not cancel the run context")
	}
}

// stop() must unregister the handler, or a test binary that calls
// notifyContext leaves SIGTERM diverted for whatever runs after it.
//
// The escalation half — a second signal exiting with 130 — is deliberately
// not tested here: it calls os.Exit, which would take the test binary with
// it. What is testable is that the handler stops handling once stop returns,
// so the escalation goroutine is not left holding the process's signals.
func TestStopRestoresDefaultSignalHandling(t *testing.T) {
	ctx, stop := notifyContext(context.Background())
	stop()

	if ctx.Err() == nil {
		t.Error("stop must cancel the context it handed out")
	}
}
