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
)

// CommandRunner runs external commands and looks up binaries. Production
// code uses DefaultRunner; tests inject a fake to script command output
// and simulate missing tools (e.g. Trivy not installed).
type CommandRunner interface {
	// Run executes name with args and returns its stdout. A non-zero exit is
	// returned as an error whose message includes the command's stderr.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// LookPath reports the absolute path of a binary, or an error if it
	// is not on PATH. Used by checkers' Available() gates.
	LookPath(name string) (string, error)
}

// DefaultRunner is the real CommandRunner backed by os/exec.
type DefaultRunner struct{}

// Run executes the command and returns its stdout.
func (DefaultRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return out, withStderr(err)
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
