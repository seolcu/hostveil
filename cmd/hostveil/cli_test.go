package main

import (
	"context"
	"encoding/json"
	"flag"
	"strconv"
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
		{"high only", []model.Finding{finding(model.SeverityHigh, false)}, 1},
		{"medium only", []model.Finding{finding(model.SeverityMedium, false)}, 0},
		{"low only", []model.Finding{finding(model.SeverityLow, false)}, 0},
		{
			"a fixed high finding does not gate",
			[]model.Finding{finding(model.SeverityHigh, true)},
			0,
		},
		{
			"one unfixed high finding among fixed ones still gates",
			[]model.Finding{finding(model.SeverityHigh, true), finding(model.SeverityHigh, false)},
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

// A failed domain contributes no findings, so before this an unreachable
// Docker socket silenced the two heaviest axes and the pipeline saw exit 0.
// A blind scan and a clean host must not look the same to the one consumer
// that never reads the output.
func TestExitCodeReflectsDomainState(t *testing.T) {
	domain := func(st model.ScanState) model.DomainResult {
		return model.DomainResult{Source: model.SourceCompose, State: st}
	}
	for _, tc := range []struct {
		name    string
		fs      []model.Finding
		domains []model.DomainResult
		want    int
	}{
		{"a failed domain is not a clean host", nil, []model.DomainResult{domain(model.ScanError)}, 3},
		{"a skipped domain is ordinary", nil, []model.DomainResult{domain(model.ScanSkipped)}, 0},
		{"a degraded domain is reported, not gated", nil, []model.DomainResult{domain(model.ScanDegraded)}, 0},
		{"everything ran and found nothing", nil, []model.DomainResult{domain(model.ScanDone)}, 0},
		{
			// Findings win: the gate exists to answer "is this host exposed",
			// and a domain that also failed does not make that less true.
			"findings outrank an incomplete scan",
			[]model.Finding{finding(model.SeverityHigh, false)},
			[]model.DomainResult{domain(model.ScanError)},
			1,
		},
		{
			"one failed domain among healthy ones still counts",
			nil,
			[]model.DomainResult{domain(model.ScanDone), domain(model.ScanError), domain(model.ScanSkipped)},
			3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := exitCode(model.Report{Findings: tc.fs, Domains: tc.domains})
			if got != tc.want {
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

// A mistyped --theme is a usage error, not a silent fall back to the default:
// the user asked for something specific and did not get it. It is caught
// before the TUI's terminal check, so it reports the same way when piped.
// The subcommands are called directly rather than through run(): run() would
// re-exec under sudo, and a *valid* theme would leave cmdServe listening
// forever. Both must refuse before either of those can happen.
func TestUnknownThemeIsAUsageError(t *testing.T) {
	for name, cmd := range map[string]func(context.Context, []string) int{"tui": cmdTUI, "serve": cmdServe} {
		if code := cmd(context.Background(), []string{"--theme", "no-such-theme"}); code != 2 {
			t.Errorf("%s --theme no-such-theme exited %d, want 2", name, code)
		}
	}
}

// resolveTheme is the one place the precedence lives; every UI goes through
// it, so a valid flag must survive whatever the environment happens to say.
func TestResolveThemePrefersTheFlag(t *testing.T) {
	t.Setenv(themeEnv, "gruvbox")
	got, err := resolveTheme("nord")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "nord" {
		t.Errorf("resolveTheme = %q, want nord", got.ID)
	}
}

func TestResolveThemeReadsTheEnvironment(t *testing.T) {
	t.Setenv(themeEnv, "tokyonight")
	got, err := resolveTheme("")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "tokyonight" {
		t.Errorf("resolveTheme = %q, want tokyonight", got.ID)
	}
}

// TestTheGateStillMeansWhatItMeant is the compatibility claim the severity
// change makes to everyone running `hostveil scan` in CI.
//
// The gate is documented in two languages as "exit 1 when any unfixed finding
// is Critical or High". Those two levels became one — now called High — and the
// promise is that the *set* did not move: everything that gated before gates
// now, and nothing that did not has started to. A pipeline that has been
// green stays green for the same reasons.
//
// It is written against the old scale's ordinals rather than its constants,
// which no longer exist. That is deliberate: the numbers are what a snapshot
// on disk holds, and reading one back is the only way left to name a level
// this build has never heard of.
func TestTheGateStillMeansWhatItMeant(t *testing.T) {
	// The four-level scale, by the ordinal each level was serialized as, and
	// whether it gated.
	for _, tc := range []struct {
		ordinal int
		name    string
		gated   bool
	}{
		{0, "critical", true},
		{1, "high", true},
		{2, "medium", false},
		{3, "low", false},
	} {
		var sev model.Severity
		if err := json.Unmarshal([]byte(strconv.Itoa(tc.ordinal)), &sev); err != nil {
			t.Fatalf("%s (%d) no longer reads at all: %v", tc.name, tc.ordinal, err)
		}
		want := 0
		if tc.gated {
			want = 1
		}
		if got := exitCode(model.Report{Findings: []model.Finding{finding(sev, false)}}); got != want {
			t.Errorf("a finding that was %s exits %d, and used to exit %d — the CI gate moved",
				tc.name, got, want)
		}
	}
}
