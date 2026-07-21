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

	cmd, args := resolveCommand(args, isInteractive())

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

// resolveCommand decides which subcommand to run and what arguments it
// receives. It is separate from run so the dispatch rules can be tested
// without a scan, a terminal, or a sudo prompt.
//
// The three cases, in order:
//
//   - A bare word is the subcommand.
//   - A leading flag with no subcommand means scan. Flags only ever apply to
//     scan (cmdTUI accepts none), so scan's parser gets to accept or reject
//     them. This case used to fall through to the interactive one, which
//     opened the TUI and discarded the flags: on a terminal `hostveil --json`
//     printed no JSON and `hostveil --bogus` reported no error, while both
//     behaved correctly when piped. Same input, divergent behavior by
//     TTY-ness, and the silent branch was the interactive one.
//   - Nothing at all opens the TUI on a terminal, or prints a scan when
//     piped, which is what makes `hostveil > report.txt` do something useful.
func resolveCommand(args []string, interactive bool) (string, []string) {
	switch {
	case len(args) > 0 && !strings.HasPrefix(args[0], "-"):
		return args[0], args[1:]
	case len(args) > 0:
		return "scan", args
	case interactive:
		return "tui", args
	default:
		return "scan", args
	}
}

func printUsage(w *os.File) {
	fmt.Fprint(w, `hostveil — guided hardening for self-hosted Linux servers

Usage:
  hostveil                       Open the interactive TUI (on a terminal)
  hostveil scan [flags]          Scan the host and report security findings
  hostveil tui                   Open the interactive TUI explicitly
  hostveil fix <id> [flags]      Preview and apply the fix for a finding
  hostveil fix --all             Apply every safe (Auto) fix at once
  hostveil explain <id> [flags]  Explain a finding (optionally via local AI)
  hostveil serve [--addr]        Serve the localhost web dashboard (alias: web)
  hostveil rollback <id>         Undo a previously applied fix
  hostveil history               List applied fixes and their rollback IDs
  hostveil version               Print the version (also: --version, -V)
  hostveil help                  Show this help (also: --help, -h)

Scan flags:
  -v, --verbose   Show each finding's description and fix guidance
  --json          Output the report as JSON
  --no-color      Disable colored output

Fix flags:
  --all           Apply every safe (Auto) fix; Review and Manual are left alone
  --service NAME  Disambiguate a finding that affects multiple services
  --action N      For Review fixes, pick alternative N (0-based)
  --yes           Apply without an interactive confirmation

Explain flags:
  --service NAME  Disambiguate a finding that affects multiple services
  --ai            Add a plain-language explanation from a local Ollama model

Exit status:
  hostveil scan exits 1 when any unfixed finding is Critical or High, and 0
  otherwise — useful as a CI or cron gate. Other commands exit 0 on success,
  1 on failure, and 2 on a usage error.

Environment:
  HOSTVEIL_NO_SUDO=1   Never re-exec under sudo (for scripts and CI)
  NO_COLOR=1           Disable colored output
`)
}
