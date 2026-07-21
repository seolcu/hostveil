package main

import (
	"flag"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func finding(sev model.Severity, fixed bool) model.Finding {
	f := model.NewFinding("ssh.rootlogin", "t", sev, model.SourceSSH, model.RemediationManual)
	f.Fixed = fixed
	return f
}

// exitCode is hostveil's CI contract and had no test at all. A regression
// here silently turns every pipeline gate into a no-op (always 0) or a
// permanent red (always 1), and nothing else in the suite would notice.
func TestExitCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		fs   []model.Finding
		want int
	}{
		{"no findings", nil, 0},
		{"critical", []model.Finding{finding(model.SeverityCritical, false)}, 1},
		{"high", []model.Finding{finding(model.SeverityHigh, false)}, 1},
		{"medium only", []model.Finding{finding(model.SeverityMedium, false)}, 0},
		{"low only", []model.Finding{finding(model.SeverityLow, false)}, 0},
		{
			"a fixed critical does not gate",
			[]model.Finding{finding(model.SeverityCritical, true)},
			0,
		},
		{
			"one unfixed high among fixed criticals still gates",
			[]model.Finding{finding(model.SeverityCritical, true), finding(model.SeverityHigh, false)},
			1,
		},
		{
			"medium and low together never gate",
			[]model.Finding{finding(model.SeverityMedium, false), finding(model.SeverityLow, false)},
			0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(model.Report{Findings: tc.fs}); got != tc.want {
				t.Errorf("exitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

// -h is a request, not a mistake. Go's flag package reports it as
// flag.ErrHelp after printing usage, and treating that as a parse failure
// made `hostveil scan --help` exit 2. The top-level form was fixed in #520
// and the same bug survived one level down in every subcommand.
func TestParseFlagsTreatsHelpAsSuccess(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		fs.SetOutput(discard{})
		fs.Bool("json", false, "")
		if code := parseFlags(fs, []string{arg}); code != 0 {
			t.Errorf("parseFlags(%q) = %d, want 0", arg, code)
		}
	}
}

func TestParseFlagsRejectsUnknownFlag(t *testing.T) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(discard{})
	fs.Bool("json", false, "")
	if code := parseFlags(fs, []string{"--nope"}); code != 2 {
		t.Errorf("parseFlags(--nope) = %d, want 2", code)
	}
}

func TestParseFlagsCarriesOnWhenValid(t *testing.T) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "")
	if code := parseFlags(fs, []string{"--json"}); code != -1 {
		t.Fatalf("parseFlags = %d, want -1 (carry on)", code)
	}
	if !*jsonOut {
		t.Error("--json was not applied")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// needsRoot must not elevate for commands that only print, or a user
// checking the version gets a password prompt.
func TestNeedsRootExcludesPrintOnlyCommands(t *testing.T) {
	for _, cmd := range []string{"version", "help", "bogus", ""} {
		if needsRoot(cmd) {
			t.Errorf("%q should not trigger elevation", cmd)
		}
	}
	for _, cmd := range []string{"scan", "tui", "fix", "serve", "web", "explain", "rollback", "history"} {
		if !needsRoot(cmd) {
			t.Errorf("%q reads root-only state and should elevate", cmd)
		}
	}
}

// The dispatch bug: a leading flag set explicit=false, which on a terminal
// picked the TUI — and cmdTUI ignores its arguments entirely. So `hostveil
// --json` opened the TUI and printed no JSON, and `hostveil --bogus` opened
// the TUI and reported no error, while both behaved correctly when piped.
func TestResolveCommand(t *testing.T) {
	for _, tc := range []struct {
		name        string
		args        []string
		interactive bool
		wantCmd     string
		wantArgs    []string
	}{
		{"bare word is the subcommand", []string{"scan", "--json"}, true, "scan", []string{"--json"}},
		{"nothing on a terminal opens the TUI", nil, true, "tui", nil},
		{"nothing when piped prints a scan", nil, false, "scan", nil},

		// The regressions. Both must reach scan with the flag intact, on a
		// terminal as well as piped, so the flag is either honored or refused
		// rather than silently dropped.
		{"--json on a terminal reaches scan", []string{"--json"}, true, "scan", []string{"--json"}},
		{"--json piped reaches scan", []string{"--json"}, false, "scan", []string{"--json"}},
		{"unknown flag reaches scan to be rejected", []string{"--bogus"}, true, "scan", []string{"--bogus"}},
		{"-v shorthand reaches scan", []string{"-v"}, true, "scan", []string{"-v"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, args := resolveCommand(tc.args, tc.interactive)
			if cmd != tc.wantCmd {
				t.Errorf("cmd = %q, want %q", cmd, tc.wantCmd)
			}
			if len(args) != len(tc.wantArgs) {
				t.Fatalf("args = %v, want %v", args, tc.wantArgs)
			}
			for i := range args {
				if args[i] != tc.wantArgs[i] {
					t.Errorf("args = %v, want %v", args, tc.wantArgs)
				}
			}
		})
	}
}

// TTY-ness must never change whether a flag is honored — only what happens
// when there are no arguments at all.
func TestFlagHandlingDoesNotDependOnTTY(t *testing.T) {
	for _, args := range [][]string{{"--json"}, {"--bogus"}, {"-v", "--no-color"}, {"scan"}} {
		tty, _ := resolveCommand(args, true)
		piped, _ := resolveCommand(args, false)
		if tty != piped {
			t.Errorf("%v dispatches to %q on a terminal but %q when piped", args, tty, piped)
		}
	}
}
