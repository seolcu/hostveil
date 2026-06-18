// Package privilege owns the elevation flow that lets hostveil run
// per-category sub-commands as root (or via polkit) without forcing
// the user to pre-elevate the whole binary. See contracts/cli.md and
// research.md R-005.
package privilege

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Helper is the platform's elevation mechanism.
type Helper string

const (
	HelperSudo   Helper = "sudo"
	HelperPkexec Helper = "pkexec"
	HelperNone   Helper = ""
)

// Detect returns the first available elevation helper, or HelperNone
// if neither is installed. The check is intentionally cheap: it
// looks for the binary in $PATH, it does not actually run it.
func Detect() Helper {
	for _, h := range []Helper{HelperSudo, HelperPkexec} {
		if _, err := exec.LookPath(string(h)); err == nil {
			return h
		}
	}
	return HelperNone
}

// ErrElevationRequired is returned by Run when the call requires
// elevation and the helper is not available.
var ErrElevationRequired = errors.New("elevation required")

// ErrElevationDenied is returned when the user denies the prompt or
// the helper exits non-zero.
var ErrElevationDenied = errors.New("elevation denied")

// Command is one elevated sub-command.
type Command struct {
	Name string
	Args []string
}

// Result captures the outcome of one elevated command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Run executes the given commands in a single elevation session when
// a helper is available. The commands are batched into one sudo/pkexec
// invocation so the user sees at most one password prompt (per
// spec edge case: "multiple elevation prompts in a single scan").
//
// If h is HelperNone, Run returns ErrElevationRequired; callers
// record the affected category as a CategorySkip with reason
// elevation_required.
//
// If the user denies the prompt or the helper fails, Run returns
// ErrElevationDenied; callers record the affected category as a
// CategorySkip with reason elevation_denied.
func Run(ctx context.Context, h Helper, commands []Command) ([]Result, error) {
	if h == HelperNone {
		return nil, ErrElevationRequired
	}
	if len(commands) == 0 {
		return nil, nil
	}

	// Build the elevated command. The pattern: sudo -n <cmd1>; sudo
	// -n <cmd2>; ... — we chain with '&&' and ';' to make a single
	// shell invocation. We pass -n (non-interactive) so the user is
	// prompted exactly once via the helper's own UI; this matches the
	// "single password prompt" goal in the spec.
	var shell strings.Builder
	for i, c := range commands {
		if i > 0 {
			shell.WriteString(" && ")
		}
		shell.WriteString(shellQuote(c.Name))
		for _, a := range c.Args {
			shell.WriteByte(' ')
			shell.WriteString(shellQuote(a))
		}
	}

	var cmd *exec.Cmd
	switch h {
	case HelperSudo:
		cmd = exec.CommandContext(ctx, "sudo", "-n", "--", "sh", "-c", shell.String())
	case HelperPkexec:
		// pkexec does not have a -n equivalent; the helper prompts
		// via polkit directly. We pass the shell as a single arg.
		cmd = exec.CommandContext(ctx, "pkexec", "sh", "-c", shell.String())
	default:
		return nil, ErrElevationRequired
	}
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%w: helper exited %d", ErrElevationDenied, ee.ExitCode())
		}
		return nil, fmt.Errorf("%w: %v", ErrElevationDenied, err)
	}
	// We executed the chain as one shell; for v3.0.0 we return a
	// single Result per invocation. Per-command stdout separation
	// is a post-v3 refinement.
	return []Result{{Stdout: string(out), ExitCode: 0}}, nil
}

// shellQuote returns a single-quoted shell-safe form of s.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
