// Package platform is hostveil's seam to the host operating system:
// running commands, looking up binaries, and detecting the distro,
// package manager, and service manager. Every checker and fix reaches the
// OS through this package so they can be unit-tested against a fake
// runner without touching the real system.
package platform

import (
	"context"
	"os/exec"
)

// CommandRunner runs external commands and looks up binaries. Production
// code uses DefaultRunner; tests inject a fake to script command output
// and simulate missing tools (e.g. Trivy not installed).
type CommandRunner interface {
	// Run executes name with args and returns its combined stdout. A
	// non-zero exit is returned as an error.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// LookPath reports the absolute path of a binary, or an error if it
	// is not on PATH. Used by checkers' Available() gates.
	LookPath(name string) (string, error)
}

// DefaultRunner is the real CommandRunner backed by os/exec.
type DefaultRunner struct{}

// Run executes the command and returns its stdout.
func (DefaultRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
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
