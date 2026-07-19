// Command hostveil is a guided hardening tool for self-hosted Linux
// servers: it scans the host for the security mistakes most likely to get
// a non-expert self-hoster hacked, explains them in plain language, and
// (in later phases) fixes them safely with preview, backup, and rollback.
package main

import (
	"fmt"
	"os"
	"strings"
)

// version is the build version, overridden via -ldflags at release time.
var version = "v3-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// Top-level help/version flags are handled before subcommand dispatch so
	// they behave like the bare-word `help`/`version` subcommands. Otherwise a
	// leading dash-flag is never promoted to a command and leaks into the
	// default `scan` flag set — `hostveil --help` would print scan's usage and
	// `hostveil --version` would error with "flag provided but not defined".
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help":
			printUsage(os.Stdout)
			return 0
		case "-V", "--version":
			fmt.Println("hostveil", version)
			return 0
		}
	}

	// With an explicit subcommand, dispatch to it. With none, open the TUI
	// on an interactive terminal, otherwise print a scan (script-friendly).
	explicit := len(args) > 0 && !strings.HasPrefix(args[0], "-")
	cmd := "scan"
	switch {
	case explicit:
		cmd, args = args[0], args[1:]
	case isInteractive():
		cmd = "tui"
	}

	maybeElevate(cmd) // on success the process is replaced by sudo and does not return

	switch cmd {
	case "scan":
		return cmdScan(args)
	case "tui":
		return cmdTUI(args)
	case "fix":
		return cmdFix(args)
	case "serve", "web":
		return cmdServe(args)
	case "explain":
		return cmdExplain(args)
	case "rollback":
		return cmdRollback(args)
	case "history":
		return cmdHistory(args)
	case "version":
		fmt.Println("hostveil", version)
		return 0
	case "help":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "hostveil: unknown command %q\n\n", cmd)
		printUsage(os.Stderr)
		return 2
	}
}

func printUsage(w *os.File) {
	fmt.Fprint(w, `hostveil — guided hardening for self-hosted Linux servers

Usage:
  hostveil                       Open the interactive TUI (on a terminal)
  hostveil scan [flags]          Scan the host and report security findings
  hostveil tui                   Open the interactive TUI explicitly
  hostveil fix <id> [flags]      Preview and apply the fix for a finding
  hostveil explain <id> [--ai]   Explain a finding (optionally via local AI)
  hostveil serve [--addr]        Serve the localhost web dashboard
  hostveil rollback <id>         Undo a previously applied fix
  hostveil history               List applied fixes and their rollback IDs
  hostveil version               Print the version (also: --version, -V)
  hostveil help                  Show this help (also: --help, -h)

Scan flags:
  -v, --verbose   Show each finding's description and fix guidance
  --json          Output the report as JSON
  --no-color      Disable colored output

Fix flags:
  --service NAME  Disambiguate a finding that affects multiple services
  --action N      For Review fixes, pick alternative N (0-based)
  --yes           Apply without an interactive confirmation
`)
}
