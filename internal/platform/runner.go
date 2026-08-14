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
	"os"
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

	// MaxOutput bounds how much stdout one command may hand back. Zero means
	// maxOutput, and it is a field for the same reason Timeout is: proving
	// the ceiling exists should not require producing 128 MiB to hit it.
	MaxOutput int
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
//
// # The locale is pinned, and it has to be
//
// Every parser in internal/check that matches a word rather than a number is
// reading translated text unless the command is told not to translate. This
// inherited the operator's environment, and `sudo` keeps LANG and LC_* by
// default, so `hostveil scan` on a German or Japanese host asked apt in German
// and then looked for English.
//
// The one that mattered: apt's `[upgradable from: %s]` is translated in
// twenty-one locales, and countAptSecurityUpdates skips any line that does not
// contain that exact English text. On such a host the pending-security-updates
// count came out zero however many were waiting — a clean report on an
// unpatched machine, which is the failure class this whole tool refuses.
//
// LC_ALL rather than LANG, and this is the part worth remembering: gettext
// honours LANGUAGE over LANG, so setting LANG alone leaves a desktop's
// `LANGUAGE=de:en` in charge. LANGUAGE is ignored when the locale is C, which
// is why this one variable is enough. Verified against real apt: with
// `LANGUAGE=de LANG=de_DE.UTF-8 LC_ALL=C` it prints "Listing...", and dropping
// the LC_ALL prints "Auflistung…".
//
// The rest of the environment is kept. Commands need PATH to be found at all,
// and DOCKER_HOST to reach a daemon that is not on this machine.
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
	// G204: this is the seam. Every command hostveil runs arrives here as
	// argv from a checker or a fix — never a shell string, which is the
	// property that matters and the one gosec cannot see. Refusing a
	// variable command here would leave the tool able to run nothing.
	//nolint:gosec // G204: the command seam; argv only, never a shell
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = waitDelay
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	// Bounded rather than cmd.Output(), which reads until the pipe closes.
	// Time was bounded here from the start and memory was not, and the two
	// fail differently: a command that hangs is killed at the deadline, while
	// one that streams is held in full until it stops. The CVE checker runs
	// several of these at once against a host that is often a 1 GB VPS, and
	// `serve` does it as root — an OOM kill there ends the dashboard for
	// every request in flight.
	//
	// stdout and stderr are captured separately because withStderr needs the
	// message, and setting cmd.Stderr means exec no longer fills
	// ExitError.Stderr for it.
	cap_ := r.MaxOutput
	if cap_ <= 0 {
		cap_ = maxOutput
	}
	stdout := &capped{limit: cap_}
	stderr := &capped{limit: maxStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()

	// Overflow returns no output at all. Handing back the first 128 MiB of a
	// JSON document would give a checker something that parses to a smaller,
	// wrong answer, which is the failure this project spends most of its
	// tests on: a partial look reported as a finished one.
	if stdout.overflow {
		return nil, fmt.Errorf("%s produced more than %d bytes of output and was not read; "+
			"this domain is reported as failed rather than judged on part of it", name, cap_)
	}
	return stdout.buf, describeContext(ctx, name, limit, withStderr(err, stderr.buf))
}

// maxOutput bounds what one command may hand back.
//
// Generous on purpose: Trivy's JSON for a large image runs to tens of
// megabytes and has to fit. This is a ceiling on a runaway, not a budget.
const maxOutput = 128 << 20

// maxStderrBytes bounds the diagnostic channel. cleanStderr cuts the message
// to a line anyway, so anything past this was never going to be shown.
const maxStderrBytes = 64 << 10

// capped collects output up to a limit and remembers whether more arrived.
//
// Write always reports the full length. Reporting a short write would make
// exec close the pipe and the command die of SIGPIPE, which reaches the
// operator as a broken tool rather than as output hostveil declined to hold.
type capped struct {
	buf      []byte
	limit    int
	overflow bool
}

func (c *capped) Write(p []byte) (int, error) {
	switch room := c.limit - len(c.buf); {
	case room >= len(p):
		c.buf = append(c.buf, p...)
	case room > 0:
		c.buf = append(c.buf, p[:room]...)
		c.overflow = true
	case len(p) > 0:
		c.overflow = true
	}
	return len(p), nil
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
func withStderr(err error, captured []byte) error {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return err
	}
	// Prefer what was captured here. ExitError.Stderr is only filled when
	// exec owns the buffer, which it no longer does.
	msg := cleanStderr(captured)
	if msg == "" {
		msg = cleanStderr(exitErr.Stderr)
	}
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
	argv := DockerProbeArgv()
	if _, err := r.Run(ctx, argv[0], argv[1:]...); err != nil {
		return false, "cannot reach the Docker daemon — add your user to the docker group, or re-run with sudo"
	}
	return true, ""
}

// DockerProbeArgv is the exact command DockerReachable runs.
//
// It is exported so tests script this rather than a copy of it. The argv was
// written out by hand in five test files, and a scripted command that no
// longer matches the caller's does not fail — it falls through to the fake
// runner's error path, which every checker reads as a daemon that did not
// answer. That is the same value a genuinely unreachable daemon produces, so
// a test covering the reachable case would go on passing while covering the
// opposite one.
func DockerProbeArgv() []string {
	return []string{"docker", "version", "--format", "{{.Server.Version}}"}
}
