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
	if os.Getenv("HOSTVEIL_ELEVATED") != "" {
		return // re-exec loop guard (e.g. sudo target is not root)
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
	env := append(os.Environ(), "HOSTVEIL_ELEVATED=1")
	_ = syscall.Exec(sudo, argv, env)
	// If Exec returns, it failed; fall through and run unprivileged.
}
