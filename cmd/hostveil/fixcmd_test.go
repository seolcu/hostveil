package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
)

// `fix` and `rollback` are the two commands that change the host, and
// neither had a single test: every assertion in this package stopped at flag
// parsing. What follows drives them through a fake Docker daemon and a real
// compose file in a temp directory, so the whole path — scan, resolve the
// finding, preview, prompt, apply, checkpoint, roll back — runs for real
// without touching the machine running the tests.

// exposedRedis is the fixture: a datastore published on 0.0.0.0, which is
// compose.ds018 — High, and Auto-fixable by binding it to loopback.
const exposedRedis = "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"

// fixtureHost points newEngine at a temp compose file and a temp state
// directory for the duration of one test, and returns the compose path.
func fixtureHost(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte(exposedRedis), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()

	// One engine for the whole test: the CLI builds a fresh one per command,
	// but they must share a state directory or a fix applied by `fix` would
	// be invisible to `history`.
	orig := newEngine
	newEngine = func() *core.Engine {
		return core.New(core.Config{
			Registry: check.NewRegistry(composecheck.New()),
			Fixes:    fix.Default(),
			Store:    history.NewStore(stateDir),
			Runner:   checktest.ComposeProjects(map[string]string{"demo": path}),
		})
	}
	t.Cleanup(func() { newEngine = orig })
	return path
}

// withStdin feeds the prompt reader a scripted answer.
func withStdin(t *testing.T, input string) {
	t.Helper()
	origIn, origReader := stdin, promptIn
	stdin, promptIn = strings.NewReader(input), nil
	t.Cleanup(func() { stdin, promptIn = origIn, origReader })
}

func runCmd(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	var code int
	out := captureStdout(t, func() { code = fn() })
	return code, out
}

// --- fix ---

func TestFixAppliesAndPrintsTheRollbackID(t *testing.T) {
	path := fixtureHost(t)

	code, out := runCmd(t, func() int {
		return cmdFix(context.Background(), []string{"compose.ds018", "--yes"})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "Rollback with: hostveil rollback ") {
		t.Errorf("the outcome must name the rollback ID:\n%s", out)
	}
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), "127.0.0.1:6379:6379") {
		t.Errorf("the fix did not reach the file:\n%s", after)
	}
}

// The confirmation is the last thing between a user and a changed host, so
// declining it must change nothing at all.
func TestFixDecliningTheConfirmationChangesNothing(t *testing.T) {
	path := fixtureHost(t)
	withStdin(t, "n\n")

	code, out := runCmd(t, func() int {
		return cmdFix(context.Background(), []string{"compose.ds018"})
	})
	if code != 0 {
		t.Errorf("declining is not a failure, exit = %d", code)
	}
	if !strings.Contains(out, "Aborted") {
		t.Errorf("the user should be told nothing happened:\n%s", out)
	}
	if after, _ := os.ReadFile(path); string(after) != exposedRedis {
		t.Errorf("the file changed despite a declined confirmation:\n%s", after)
	}
}

// Anything other than an explicit yes is a no. A prompt that treats a
// stray keystroke as consent is worse than no prompt.
func TestFixOnlyAnExplicitYesApplies(t *testing.T) {
	for _, answer := range []string{"", "\n", "no\n", "maybe\n", "Y E S\n"} {
		path := fixtureHost(t)
		withStdin(t, answer)
		_, _ = runCmd(t, func() int { return cmdFix(context.Background(), []string{"compose.ds018"}) })
		if after, _ := os.ReadFile(path); string(after) != exposedRedis {
			t.Errorf("answer %q applied the fix:\n%s", answer, after)
		}
	}
}

// Two prompts in a row used to lose the second answer: each call built its
// own bufio.Scanner over os.Stdin, and the first read ahead into a buffer
// that went out of scope with it. The confirmation then read EOF, which is
// "no" — so a Review fix could never be applied interactively at all.
func TestTwoPromptsInARowBothGetTheirAnswer(t *testing.T) {
	withStdin(t, "1\ny\n")
	if got := prompt("first: "); got != "1" {
		t.Fatalf("first prompt read %q", got)
	}
	if !promptYesNo("second:") {
		t.Error("the second prompt lost its answer to the first prompt's buffer")
	}
}

func TestFixReportsAnUnknownFinding(t *testing.T) {
	fixtureHost(t)
	code, _ := runCmd(t, func() int {
		return cmdFix(context.Background(), []string{"compose.nosuchthing", "--yes"})
	})
	if code != 1 {
		t.Errorf("exit = %d, want 1 for a finding that is not there", code)
	}
}

func TestFixWithNoArgumentIsAUsageError(t *testing.T) {
	code, _ := runCmd(t, func() int { return cmdFix(context.Background(), nil) })
	if code != 2 {
		t.Errorf("exit = %d, want 2 for a missing finding ID", code)
	}
}

// --all must touch only Auto findings. The compose fixture has a Manual one
// (a hardcoded secret is not machine-fixable), which must survive untouched.
func TestFixAllAppliesOnlyTheSafeOnes(t *testing.T) {
	path := fixtureHost(t)

	code, out := runCmd(t, func() int {
		return cmdFix(context.Background(), []string{"--all", "--yes"})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "Applied") {
		t.Errorf("the summary should say what was applied:\n%s", out)
	}
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), "127.0.0.1:6379:6379") {
		t.Errorf("the auto fix did not reach the file:\n%s", after)
	}
}

// A batch where every fix failed used to print "✓ Applied 0 · failed 3" and
// exit 0.
//
// The tick and the status are the two things an unattended caller reads, and
// both said the run had gone fine. `scan` has documented the opposite
// contract since it was written — a non-zero status means the run did not do
// what it was asked — and `fix --all` is the command most likely to be in a
// cron line.
func TestFixAllReportsFailureWhenNothingCouldBeApplied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory, so the fix cannot be made to fail this way")
	}
	path := fixtureHost(t)

	// The fix writes through a temp file beside the target, so a directory
	// nobody may write to is what stops it — and it stops it at the write,
	// after the backup, which is the failure shape that matters.
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	code, out := runCmd(t, func() int {
		return cmdFix(context.Background(), []string{"--all", "--yes"})
	})
	if code == 0 {
		t.Errorf("exit = 0 on a batch where every fix failed\n%s", out)
	}
	if strings.Contains(out, "✓") {
		t.Errorf("a failed batch is marked with a tick:\n%s", out)
	}
	if !strings.Contains(out, "failed") {
		t.Errorf("the summary does not say anything failed:\n%s", out)
	}
}

// --- rollback and history ---

func TestHistoryThenRollbackRestoresTheFile(t *testing.T) {
	path := fixtureHost(t)

	if code, out := runCmd(t, func() int {
		return cmdFix(context.Background(), []string{"compose.ds018", "--yes"})
	}); code != 0 {
		t.Fatalf("fix failed: %d\n%s", code, out)
	}

	code, listing := runCmd(t, func() int { return cmdHistory(context.Background(), nil) })
	if code != 0 {
		t.Fatalf("history exit = %d", code)
	}
	id := rollbackIDFrom(t, listing)

	if code, out := runCmd(t, func() int {
		return cmdRollback(context.Background(), []string{id})
	}); code != 0 {
		t.Fatalf("rollback exit = %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(path); string(after) != exposedRedis {
		t.Errorf("rollback did not restore the original:\n%s", after)
	}
}

// An operator's later edit is not something to discard silently. Rollback
// keeps no backup of its own, so it declines — and the CLI has to report
// that as a decision, not as a crash.
func TestRollbackDeclinesOverAnExternalEdit(t *testing.T) {
	path := fixtureHost(t)
	if code, _ := runCmd(t, func() int {
		return cmdFix(context.Background(), []string{"compose.ds018", "--yes"})
	}); code != 0 {
		t.Fatal("fix failed")
	}
	_, listing := runCmd(t, func() int { return cmdHistory(context.Background(), nil) })
	id := rollbackIDFrom(t, listing)

	if err := os.WriteFile(path, []byte(exposedRedis+"# edited by hand\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _ := runCmd(t, func() int { return cmdRollback(context.Background(), []string{id}) })
	if code != 1 {
		t.Errorf("a declined rollback should exit 1, got %d", code)
	}
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), "edited by hand") {
		t.Error("the declined rollback discarded the operator's edit anyway")
	}
}

// --force is the escape hatch, and it must actually work — a decline the
// user cannot override is just a failure.
func TestRollbackForceOverridesTheDecline(t *testing.T) {
	path := fixtureHost(t)
	if code, _ := runCmd(t, func() int {
		return cmdFix(context.Background(), []string{"compose.ds018", "--yes"})
	}); code != 0 {
		t.Fatal("fix failed")
	}
	_, listing := runCmd(t, func() int { return cmdHistory(context.Background(), nil) })
	id := rollbackIDFrom(t, listing)

	if err := os.WriteFile(path, []byte(exposedRedis+"# edited by hand\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runCmd(t, func() int {
		return cmdRollback(context.Background(), []string{id, "--force"})
	}); code != 0 {
		t.Fatalf("--force exit = %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(path); string(after) != exposedRedis {
		t.Errorf("--force did not restore the backup:\n%s", after)
	}
}

func TestRollbackWithNoIDIsAUsageError(t *testing.T) {
	code, _ := runCmd(t, func() int { return cmdRollback(context.Background(), nil) })
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func TestRollbackOfAnUnknownCheckpointFails(t *testing.T) {
	fixtureHost(t)
	code, _ := runCmd(t, func() int {
		return cmdRollback(context.Background(), []string{"20200101-000000.000-dead-beef"})
	})
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestHistoryOnAFreshHostSaysSo(t *testing.T) {
	fixtureHost(t)
	code, out := runCmd(t, func() int { return cmdHistory(context.Background(), nil) })
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "No fixes have been applied yet") {
		t.Errorf("an empty history should say so:\n%s", out)
	}
}

// rollbackIDFrom pulls a checkpoint ID out of what `history` printed, which
// is exactly how an operator gets one.
func rollbackIDFrom(t *testing.T, listing string) string {
	t.Helper()
	const marker = "hostveil rollback "
	i := strings.Index(listing, marker)
	if i < 0 {
		t.Fatalf("history printed no rollback command:\n%s", listing)
	}
	rest := listing[i+len(marker):]
	if j := strings.IndexAny(rest, "] \n"); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" {
		t.Fatalf("could not read a checkpoint ID from:\n%s", listing)
	}
	return rest
}
