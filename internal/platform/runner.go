// Package platform is hostveil's seam to the host operating system:
// running commands, looking up binaries, and detecting the distro,
// package manager, and service manager. Every checker and fix reaches the
// OS through this package so they can be unit-tested against a fake
// runner without touching the real system.
package platform

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CommandRunner runs external commands and looks up binaries. Production
// code uses DefaultRunner; tests inject a fake to script command output
// and simulate missing tools (e.g. Trivy not installed).
//
// Implementations must be safe for concurrent use. Checkers all run at once,
// and some (the CVE checker, scanning several images) call the runner from
// several goroutines of their own. DefaultRunner is stateless, so this costs
// production nothing; a fake that records what it was called with needs a
// mutex around the recording.
type CommandRunner interface {
	// Run executes name with args and returns its stdout. A non-zero exit is
	// returned as an error whose message includes the command's stderr.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// LookPath reports the absolute path of a binary, or an error if it
	// is not on PATH. Used by checkers' Available() gates.
	LookPath(name string) (string, error)
}

// DefaultRunner is the real CommandRunner backed by os/exec.
type DefaultRunner struct {
	// Timeout bounds a command whose caller set no deadline. Zero means
	// DefaultTimeout, which is what every production call site wants; it is a
	// field so a test can assert the bound exists without waiting for it.
	Timeout time.Duration
}

// DefaultTimeout bounds any command whose caller set no deadline of its own.
//
// Nothing hostveil asks the host is a long question: `ss -tlnp`, `docker
// inspect`, `apt list --upgradable`, `sshd -T`. What they have in common is
// that each talks to a daemon or a package database that can stop answering
// while the socket stays open — a wedged Docker daemon is the everyday case —
// and a read from one of those blocks forever, not briefly. Thirty seconds is
// far more than any of them needs and still bounded.
//
// The bound matters more here than the exact number, because a scan runs its
// checkers concurrently behind a single-flight cache: one command that never
// returns parks every checker waiting on the same command with it, and the
// user sees "scanning: container cve firewall" until they kill the process.
const DefaultTimeout = 30 * time.Second

// waitDelay bounds the wait for output after the process itself is gone.
//
// exec.CommandContext kills the process on cancellation, but Output() also
// waits for the read of the stdout pipe to finish, and a grandchild that
// inherited the write end keeps it open after its parent dies. `docker
// compose` shelling out is exactly that shape. Without a WaitDelay the
// timeout kills the command and Wait blocks anyway, which is the same hang
// wearing a different hat.
const waitDelay = 2 * time.Second

// Run executes the command and returns its stdout.
//
// A caller that set its own deadline keeps it: the CVE checker gives Trivy
// minutes on purpose, and imposing the default on top would kill every image
// scan. The default is a floor for callers that said nothing, not a ceiling
// over callers that did.
func (r DefaultRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	limit := r.Timeout
	if limit <= 0 {
		limit = DefaultTimeout
	}
	if d, ok := ctx.Deadline(); ok {
		limit = time.Until(d)
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = waitDelay
	out, err := cmd.Output()
	return out, describeContext(ctx, name, limit, withStderr(err))
}

// describeContext turns the "signal: killed" a cancelled command reports into
// something an operator can act on. The domain reason is the only channel
// hostveil has for saying why a check did not finish, and "exit status -1" in
// it means the user has to guess between a crash, a permission problem, and a
// daemon that stopped answering.
func describeContext(ctx context.Context, name string, limit time.Duration, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%s did not respond within %s (is the daemon it talks to healthy?)",
			name, limit.Round(time.Second))
	case errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("%s was interrupted: %w", name, ctx.Err())
	}
	return err
}

// maxStderr bounds how much of a failed command's stderr reaches the error.
// Domain reasons built from these errors are rendered in every UI and
// persisted to disk with the scan report, so they must stay short and
// single-line.
const maxStderr = 200

// withStderr enriches an *exec.ExitError with the command's stderr, which
// os/exec otherwise strands on the error struct — leaving callers to report
// the useless "exit status 1". The original error is wrapped, so errors.Is
// and errors.As still work.
func withStderr(err error) error {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return err
	}
	msg := cleanStderr(exitErr.Stderr)
	if msg == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, msg)
}

// cleanStderr collapses stderr to a single truncated line. Truncation is by
// rune, not byte, so a non-ASCII message is never cut mid-sequence.
func cleanStderr(b []byte) string {
	msg := strings.Join(strings.Fields(string(b)), " ")
	if r := []rune(msg); len(r) > maxStderr {
		msg = string(r[:maxStderr]) + "…"
	}
	return msg
}

// LookPath resolves a binary on PATH.
func (DefaultRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// Has reports whether a binary is available on PATH via the runner.
func Has(r CommandRunner, name string) bool {
	_, err := r.LookPath(name)
	return err == nil
}

// DockerReachable reports whether the Docker daemon actually answers, and if
// not, why in plain language.
//
// Checkers must not settle for Has(r, "docker"): the client binary being on
// PATH says nothing about whether this user may talk to the socket. Without
// that distinction a non-root scan enumerates no containers, finds nothing,
// and reports a clean result — which for the CVE domain means a perfect
// vulnerability score on a host nobody actually scanned.
func DockerReachable(ctx context.Context, r CommandRunner) (bool, string) {
	if !Has(r, "docker") {
		return false, "Docker not installed"
	}
	if _, err := r.Run(ctx, "docker", "version", "--format", "{{.Server.Version}}"); err != nil {
		return false, "cannot reach the Docker daemon — add your user to the docker group, or re-run with sudo"
	}
	return true, ""
}
