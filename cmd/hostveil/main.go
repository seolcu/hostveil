// Command hostveil is a guided hardening tool for self-hosted Linux
// servers: it scans the host for the security mistakes most likely to get
// a non-expert self-hoster hacked, explains them in plain language, and
// fixes them safely with preview, backup, and rollback.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// version is the build version, overridden via -ldflags at release time.
var version = "v3-dev"

func main() {
	ctx, stop := notifyContext(context.Background())
	defer stop()
	os.Exit(run(ctx, os.Args[1:]))
}

// notifyContext gives the run one cancellable context, cancelled on Ctrl-C or
// SIGTERM, and makes a second signal end the process immediately.
//
// Every command threads the context down to Engine.Scan, which passes it to
// exec.CommandContext, so an interrupt actually stops the docker and trivy
// processes a scan has running rather than leaving them to finish against a
// terminal nobody is watching. Nothing was cancellable before: the TUI puts
// the terminal in raw mode and reads Ctrl-C as a key, so a scan there could
// not be interrupted at all.
//
// The escalation is the part signal.NotifyContext cannot do. Its goroutine
// consumes one signal and returns, but the handler stays registered, so from
// then on SIGINT and SIGTERM are diverted from their default disposition and
// silently dropped. Anything that ignores the cancelled context — a fix
// mid-apply, an HTTP server with no shutdown wired up — becomes
// uninterruptible, and the operator's only remaining move is SIGKILL from
// another shell. The second signal is the operator saying they meant it, so
// it exits rather than being swallowed. 130 is the conventional
// 128+SIGINT status for a program killed by an interrupt.
func notifyContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-ch
		cancel()
		<-ch
		fmt.Fprintln(os.Stderr, "\nhostveil: interrupted again, exiting now")
		os.Exit(130)
	}()

	return ctx, func() {
		signal.Stop(ch)
		cancel()
	}
}

func run(ctx context.Context, args []string) int {
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
		return cmdScan(ctx, args)
	case "tui":
		return cmdTUI(ctx, args)
	case "fix":
		return cmdFix(ctx, args)
	case "serve", "web":
		return cmdServe(ctx, args)
	case "explain":
		return cmdExplain(ctx, args)
	case "rollback":
		return cmdRollback(ctx, args)
	case "history":
		return cmdHistory(ctx, args)
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
  hostveil tui [--theme]         Open the interactive TUI explicitly
  hostveil fix <id> [flags]      Preview and apply the fix for a finding
  hostveil fix --all             Apply every safe (Auto) fix at once
  hostveil explain <id> [flags]  Explain a finding (optionally via local AI)
  hostveil serve [flags]         Serve the localhost web dashboard (alias: web)
  hostveil rollback <id> [flags] Undo a previously applied fix
  hostveil history               List applied fixes and their rollback IDs
  hostveil version               Print the version (also: --version, -V)
  hostveil help                  Show this help (also: --help, -h)

Scan flags:
  -v, --verbose   Show each finding's description and fix guidance
  --json          Output the report as JSON
  --sarif         Output the report as SARIF 2.1.0, the format CI systems
                  and GitHub code scanning ingest
  --output FILE   Write the report to FILE instead of stdout. The exit
                  status is unchanged, so a CI gate still works.
  --only LIST     Scan only these domains (comma-separated, e.g.
                  --only ssh,firewall). A partial scan is not saved as the
                  last-scan baseline and reports no delta.
  --skip LIST     Scan every domain except these (comma-separated)
  --no-color      Disable colored output

Fix flags:
  --all           Apply every safe (Auto) fix; Review and Manual are left alone
  --service NAME  Disambiguate a finding that affects multiple services
  --action N      For Review fixes, pick alternative N (0-based)
  --yes           Apply without an interactive confirmation

Explain flags:
  --service NAME  Disambiguate a finding that affects multiple services
  --ai            Add a plain-language explanation from a local Ollama model

Rollback flags:
  --force         Restore even if the file changed after the fix was applied.
                  Rollback keeps no backup of its own, so it declines by
                  default rather than discard those edits.

TUI and dashboard flags:
  --theme NAME    Color theme: onedark (default), gruvbox, nord,
                  catppuccin, tokyonight. The TUI's picker (press t) remembers
                  your choice; --theme and HOSTVEIL_THEME override it.
  --glyphs NAME   Symbol set for status markers: plain (default) or nerd.
                  nerd draws them from a patched Nerd Font; a terminal cannot
                  be asked what font it has, so this is opt-in. Also on scan,
                  and settable once with HOSTVEIL_GLYPHS.
  --addr ADDR     serve only: host:port to bind the dashboard to (default
                  127.0.0.1:8787); the port is not optional. The dashboard
                  answers only requests addressed to localhost, so this cannot
                  publish it to the network; forward the port over SSH instead.

The dashboard prints a URL carrying a one-off access token, and every route
requires it — loopback separates this host from the network, not you from the
other accounts on this machine, and serve runs as root. Open the printed URL;
the token then becomes a session cookie for that browser.

Exit status:
  hostveil scan is a CI or cron gate:
    0  the scan ran and found nothing High
    1  at least one unfixed High finding
    3  a detection domain failed outright, so the scan covered less of the
       host than it should have — a clean-looking result you cannot trust
  A domain skipped for a missing dependency, or degraded to partial coverage,
  does not change the status; both are reported in the output instead.
  Other commands exit 0 on success, 1 on failure, and 2 on a usage error.

Environment:
  HOSTVEIL_DEBUG=1     Trace every command hostveil runs against the host, to
                       stderr: what ran, how long it took, and whether it
                       failed. This is what to attach to a bug report about a
                       domain being skipped or a check reporting the wrong
                       thing. Command output is deliberately not logged — it
                       routinely contains environment variables.
  HOSTVEIL_NO_SUDO=1   Never re-exec under sudo (for scripts and CI)
  HOSTVEIL_THEME=NAME  Color theme for the TUI and the dashboard
  HOSTVEIL_GLYPHS=SET  Symbol set for the TUI and scan: plain or nerd
  NO_COLOR=1           Disable colored output

  HOSTVEIL_OLLAMA_HOST=URL     Where the optional local LLM listens
                               (default http://127.0.0.1:11434)
  HOSTVEIL_OLLAMA_MODEL=NAME   Which model to ask (default llama3.2)
  Both are advisory-only: they affect 'explain --ai' and the AI buttons in the
  TUI and dashboard, and nothing else. No score, finding, or fix depends on a
  model being reachable.
`)
}
