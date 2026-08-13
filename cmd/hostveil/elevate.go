package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// needsRoot reports whether a subcommand should auto-elevate. version/help
// and unknown commands do not.
func needsRoot(cmd string) bool {
	switch cmd {
	case "scan", "tui", "fix", "serve", "web", "explain", "rollback", "history",
		"update", "uninstall":
		return true
	}
	return false
}

// maybeElevate re-executes hostveil under sudo when a root-benefiting command
// is run without root, so plain `hostveil` behaves like `sudo hostveil` — the
// sudo password prompt is sudo's own and appears identically. On success it
// replaces the current process (execve) and does not return. It degrades to
// running unprivileged when it cannot elevate (no sudo, opt-out env, or sudo
// failure) so existing non-root partial scans still work.
func maybeElevate(cmd string) {
	if os.Geteuid() == 0 {
		return // already root (includes the re-executed sudo child)
	}
	if os.Getenv("HOSTVEIL_NO_SUDO") != "" {
		return // explicit opt-out for scripts/CI
	}
	if alreadyElevated() {
		return // sudo has already run; a second attempt would loop
	}
	if !needsRoot(cmd) {
		return
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		// Say so. The two lines below explain why hostveil is *asking* for a
		// password; this is the case where it cannot ask, and it said nothing
		// at all — so the operator learned they needed root domain by domain,
		// half way through a scan, from findings that read like a broken tool
		// rather than a missing privilege. Same channel and same reason:
		// stderr, so --json on stdout stays clean.
		fmt.Fprintln(os.Stderr, "hostveil: no sudo on PATH, so this runs as "+
			"the current user; the checks that need root will report what they could not read.")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Say why before sudo asks. A first-time user's opening interaction with
	// hostveil was otherwise a bare "[sudo] password for ..." with nothing
	// above it explaining who wanted their password or what for — the highest
	// friction possible for a tool asking to be trusted with root. This goes
	// to stderr so it never contaminates `--json` on stdout.
	fmt.Fprintln(os.Stderr, "hostveil needs root to read /etc/shadow, sshd_config, and the firewall state; re-running with sudo.")
	fmt.Fprintln(os.Stderr, "It only reads until you ask it to fix something. Set HOSTVEIL_NO_SUDO=1 to skip this (some checks will be skipped too).")

	argv := append(elevatedArgv(exe, os.Args[1:], os.Getenv), os.Args[1:]...)
	// os.Environ() unchanged, and deliberately not carrying a marker of our
	// own: sudo's env_reset drops everything it does not keep, so a variable
	// set here would not reach the child. See alreadyElevated.
	// G204: re-running hostveil's own argv under sudo is what this function
	// is for. The program is sudo at a resolved path and the arguments are
	// the ones this process was started with; there is no third party in it,
	// and refusing a variable here would mean refusing to elevate at all.
	//nolint:gosec // G204: re-execs this binary's own argv, by design
	_ = syscall.Exec(sudo, argv, os.Environ())
	// If Exec returns, it failed; fall through and run unprivileged.
}

// carriedThroughSudo are the variables a user sets on hostveil's own command
// line that have to survive the re-exec.
//
// env_reset drops all of them. That is stated in alreadyElevated's comment
// and was drawn as a conclusion about exactly one variable — the marker this
// code used to pass itself — while applying identically to every variable a
// user sets. So on the ordinary non-root host, the path hostveil documents
// most loudly did nothing: `HOSTVEIL_DEBUG=1 hostveil scan` is printed in
// `hostveil help`, in the README and on both troubleshooting pages as the
// thing to attach to a bug report, and it produced no trace at all, with no
// error and nothing to suggest the variable had been discarded. Setting a
// theme or a glyph set the same way was silently ignored too.
//
// CI never saw it because the end-to-end job runs as root with
// HOSTVEIL_NO_SUDO=1, which is both branches that skip the re-exec.
//
// The variables go across as `sudo NAME=value …` rather than through
// --preserve-env, because the assignment form is what sudo has always had and
// it says exactly what is being carried. Only variables that are actually set
// are passed, so a host where none is set builds the argv it built before.
//
// TERM, LANG and LC_* are absent on purpose: sudo's own env_keep carries
// those already. HOSTVEIL_NO_SUDO is absent because reaching this line means
// it was not set, and HOSTVEIL_ELEVATED because it is the marker whose
// non-arrival is the whole reason SUDO_USER is the loop guard.
var carriedThroughSudo = []string{
	"HOSTVEIL_DEBUG",
	"HOSTVEIL_THEME",
	"HOSTVEIL_GLYPHS",
	"HOSTVEIL_LAYOUT",
	"HOSTVEIL_OLLAMA_HOST",
	"HOSTVEIL_OLLAMA_MODEL",
	// Carried, not excused. scan elevates, so the process that would make the
	// request is the child: a variable that did not survive the re-exec would
	// look like it had turned the check off while the elevated run went on
	// making it, which is the exact failure this list exists to prevent.
	"HOSTVEIL_NO_UPDATE_CHECK",
	"NO_COLOR",
}

// elevatedArgv builds everything up to and including the executable path:
// sudo, the variable assignments that have to be carried, then the binary.
// The caller appends the original arguments.
//
// getenv is a parameter so a test can drive it without touching the real
// environment, which is process-global and would race the rest of the suite.
func elevatedArgv(exe string, _ []string, getenv func(string) string) []string {
	argv := []string{"sudo"}
	for _, name := range carriedThroughSudo {
		if v := getenv(name); v != "" {
			argv = append(argv, name+"="+v)
		}
	}
	return append(argv, exe)
}

// alreadyElevated reports whether sudo has already run, so re-running it would
// loop rather than gain anything.
//
// This used to pass HOSTVEIL_ELEVATED=1 through to the child and look for it
// there. sudo strips it: env_reset is the default on every mainstream
// distribution and keeps only what env_keep names, which is TERM, LANG, LC_*
// and a short list besides — never an application's own variable. Verified on
// Debian 13, where the child sees it empty. So the guard could not fire, and
// the case its comment named — sudo running but not yielding root — was an
// unbounded chain of sudo invocations, each one prompting for a password
// again.
//
// SUDO_USER is the signal that works, because sudo sets it in the target
// environment itself rather than passing it through. It is present even when
// the target is *not* root, which is exactly the case worth catching: on a
// host whose sudoers sets a non-root runas_default, the child comes back
// unprivileged with SUDO_USER set and stops here.
//
// HOSTVEIL_ELEVATED is still honoured. It cannot arrive through sudo, but it
// is documented, a wrapper script may set it deliberately, and reading one
// more variable costs nothing.
//
// A false positive here — SUDO_USER left in the environment by something other
// than the sudo that ran us — means hostveil does not auto-elevate and scans
// unprivileged, which it is built to do: domains that need root report Skipped
// with a reason. That is the safe direction to be wrong in, and the loop is
// not.
func alreadyElevated() bool {
	return os.Getenv("HOSTVEIL_ELEVATED") != "" || os.Getenv("SUDO_USER") != ""
}
