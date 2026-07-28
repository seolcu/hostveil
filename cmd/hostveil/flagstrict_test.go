package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr mirrors captureStdout for the stream usage errors go to.
// A usage error that does not say which flags conflict is only half an
// answer, so the message is worth asserting, not just the exit code.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

// Every subcommand exits 2 on a flag it does not accept — that is the
// documented usage-error contract, and it is what tells a user their
// invocation did not do what they typed.
//
// Three places broke it in different ways. `history` never parsed its
// arguments at all (`_ = args`), so any flag was accepted and ignored:
// `hostveil history --json` printed the human table and exited 0, which is
// the worst possible answer for a flag a scripting user would reasonably
// try. And `fix --all` parsed --service and --action into the same flag set
// as --all and then dropped them, so `fix --all --action 1` looked like it
// had chosen an alternative.
//
// Silently accepting a flag is worse than rejecting it: the user believes
// the flag did something.
func TestCommandsRejectFlagsTheyDoNotAccept(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"history rejects an unknown flag", []string{"--json"}, ""},
		{"history rejects a plausible one", []string{"--limit", "5"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := runCmd(t, func() int { return cmdHistory(context.Background(), tc.args) })
			if code != 2 {
				t.Errorf("exit %d, want 2 (usage error); output:\n%s", code, out)
			}
		})
	}
}

// --all applies every Auto fix on the host. There is no single finding to
// disambiguate with --service, and no alternative to pick with --action:
// an Auto fix has exactly one action by definition. Combining them is a
// contradiction, so it is a usage error rather than a silent drop.
func TestFixAllRejectsSingleFindingFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"with --service", []string{"--all", "--service", "cache"}},
		{"with --action", []string{"--all", "--action", "1"}},
		{"with both", []string{"--all", "--service", "cache", "--action", "0"}},
		{"with a finding id", []string{"compose.ds018", "--all"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			msg := captureStderr(t, func() {
				code = cmdFix(context.Background(), tc.args)
			})
			if code != 2 {
				t.Errorf("exit %d, want 2 (usage error); stderr:\n%s", code, msg)
			}
			if !strings.Contains(msg, "--all") {
				t.Errorf("the error does not mention --all, so it does not say what the conflict is:\n%s", msg)
			}
		})
	}
}

// The counterpart: --help is not a usage error anywhere. Go's flag package
// reports it as flag.ErrHelp after printing usage, and treating that like a
// parse failure is what made `hostveil <cmd> --help` exit 2 once already.
// history now parses its arguments, so it joins the set that could regress
// that way.
func TestHistoryHelpExitsZero(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		code, _ := runCmd(t, func() int { return cmdHistory(context.Background(), []string{arg}) })
		if code != 0 {
			t.Errorf("hostveil history %s exited %d, want 0", arg, code)
		}
	}
}
