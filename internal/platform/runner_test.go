package platform

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// A failing command's stderr is what actually explains the failure ("permission
// denied while trying to connect to the Docker daemon socket"). os/exec strands
// it on the ExitError, leaving callers to report a bare "exit status 1", which
// is what every UI would then show as the reason a domain failed.
func TestRunSurfacesStderr(t *testing.T) {
	_, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "echo 'permission denied' >&2; exit 1")
	if err == nil {
		t.Fatal("expected an error from a non-zero exit")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("stderr not surfaced in error: %q", err)
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("original exit error not preserved: %q", err)
	}
}

// Reasons built from these errors are rendered in every UI and persisted to
// disk with the scan report, so a command that dumps a megabyte of stderr must
// not drag all of it along.
func TestRunTruncatesStderr(t *testing.T) {
	_, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "head -c 5000 /dev/zero | tr '\\0' 'x' >&2; exit 1")
	if err == nil {
		t.Fatal("expected an error from a non-zero exit")
	}
	if n := utf8.RuneCountInString(err.Error()); n > maxStderr+80 {
		t.Errorf("error message not truncated: %d runes", n)
	}
}

// Truncation is by rune, so a non-ASCII message never ends in a broken
// sequence — these strings reach users' terminals.
func TestCleanStderrTruncatesOnRuneBoundary(t *testing.T) {
	got := cleanStderr([]byte(strings.Repeat("가", maxStderr*2)))
	if !utf8.ValidString(got) {
		t.Errorf("truncation split a rune: %q", got)
	}
}

// Multi-line stderr collapses to one line: DomainResult.Reason is rendered
// inline in list views that assume a single line.
func TestCleanStderrCollapsesToOneLine(t *testing.T) {
	got := cleanStderr([]byte("first line\nsecond line\n\n  third  \n"))
	if want := "first line second line third"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A command that succeeds, and one that fails silently, must be unchanged.
func TestRunLeavesOtherErrorsAlone(t *testing.T) {
	out, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "echo hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("got %q, want %q", out, "hello")
	}

	if _, err := (DefaultRunner{}).Run(context.Background(), "sh", "-c", "exit 3"); err == nil {
		t.Fatal("expected an error from a non-zero exit")
	} else if err.Error() != "exit status 3" {
		t.Errorf("empty stderr should leave the error untouched, got %q", err)
	}
}

// A command with no deadline of its own must still be bounded. Nothing
// hostveil runs is a long question, and a wedged Docker daemon answering
// never is the everyday failure — before this the scan simply hung, with no
// way out but killing the process.
func TestRunBoundsACommandThatNeverReturns(t *testing.T) {
	r := DefaultRunner{Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err := r.Run(context.Background(), "sleep", "30")
	if err == nil {
		t.Fatal("a command past the timeout must be an error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Run took %v; the timeout did not bound it", elapsed)
	}
	if !strings.Contains(err.Error(), "did not respond within") {
		t.Errorf("the error must say the command timed out, got %q", err)
	}
	if !strings.Contains(err.Error(), "sleep") {
		t.Errorf("the error must name the command, got %q", err)
	}
}

// The caller's own deadline wins. The CVE checker gives Trivy minutes on
// purpose; a runner-imposed ceiling would kill every image scan.
func TestCallerDeadlineOverridesTheDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	// A default far longer than the caller's: the caller's must be the one
	// that fires.
	r := DefaultRunner{Timeout: time.Hour}
	start := time.Now()
	if _, err := r.Run(ctx, "sleep", "30"); err == nil {
		t.Fatal("expected the caller's deadline to fire")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Run took %v; the caller's deadline was ignored", elapsed)
	}
}

// A command that outlives its parent by holding the stdout pipe open — a
// grandchild, which is how `docker compose` behaves — must not keep Wait
// blocked after the process is killed. WaitDelay is what bounds that.
func TestRunDoesNotWaitOnALingeringGrandchild(t *testing.T) {
	r := DefaultRunner{Timeout: 200 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		// The child exits immediately; the grandchild keeps the inherited
		// stdout open for far longer than the test may run.
		_, _ = r.Run(context.Background(), "sh", "-c", "sleep 30 & exit 0")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Run blocked on a grandchild holding the output pipe")
	}
}

// Cancellation and timeout are different facts and must read differently: one
// is the user's doing, the other is the host's.
func TestCancelledCommandSaysSo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	_, err := DefaultRunner{}.Run(ctx, "sleep", "30")
	if err == nil {
		t.Fatal("expected an error from a cancelled command")
	}
	if !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("a cancelled command must not read as a timeout, got %q", err)
	}
}

// Every parser in internal/check that matches a word rather than a number is
// reading translated text unless the command is told not to translate. The
// runner inherited the operator's environment, and `sudo` keeps LANG and LC_*
// by default, so `hostveil scan` on a German or Japanese host asked apt in
// German and then looked for English.
//
// The one that mattered: apt's `[upgradable from: %s]` is translated in
// twenty-one locales, and countAptSecurityUpdates skips any line without that
// exact English text. On such a host the pending-security-updates count came
// out zero however many were waiting — a clean report on an unpatched machine.
//
// LC_ALL rather than LANG, and this is the part worth remembering: gettext
// honours LANGUAGE over LANG, so setting LANG alone leaves a GNOME desktop's
// `LANGUAGE=de:en` in charge. LANGUAGE is ignored when the locale is C, which
// is why this one variable is enough — verified against real apt, where
// `LANGUAGE=de LANG=de_DE.UTF-8 LC_ALL=C` prints "Listing..." and dropping the
// LC_ALL prints "Auflistung…".
func TestRunPinsTheLocaleSoParsersReadEnglish(t *testing.T) {
	out, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "echo \"[$LC_ALL]\"")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "[C]" {
		t.Errorf("LC_ALL in the command's environment = %s, want [C]", got)
	}
}

// And the rest of the environment survives, because commands need PATH to be
// found at all and DOCKER_HOST to reach a daemon that is not on this machine.
func TestRunKeepsTheRestOfTheEnvironment(t *testing.T) {
	t.Setenv("HOSTVEIL_ENV_PROBE", "kept")
	out, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "echo \"$HOSTVEIL_ENV_PROBE:${PATH:+has-path}\"")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "kept:has-path" {
		t.Errorf("environment = %q, want the caller's variables intact", got)
	}
}
