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
	case "scan", "tui", "fix", "serve", "web", "explain", "rollback", "history":
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
		return // no sudo available — run unprivileged, checks degrade gracefully
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

	argv := append([]string{"sudo", exe}, os.Args[1:]...)
	// os.Environ() unchanged, and deliberately not carrying a marker of our
	// own: sudo's env_reset drops everything it does not keep, so a variable
	// set here would not reach the child. See alreadyElevated.
	_ = syscall.Exec(sudo, argv, os.Environ())
	// If Exec returns, it failed; fall through and run unprivileged.
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
