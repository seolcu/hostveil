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
	"runtime/debug"
	"strings"
	"syscall"
)

// version is the build version, overridden via -ldflags at release time.
var version = "v3-dev"

func main() {
	ctx, stop := notifyContext(context.Background())
	// Not deferred: os.Exit does not run deferred functions, so `defer stop()`
	// here was a line that read like cleanup and never executed one. It
	// matters less at process exit than the notifyContext comment below
	// implies — the kernel reclaims the signal handler either way — but a
	// defer that cannot run is worse than no defer: the next person moves it
	// and assumes the pattern already worked.
	code := run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
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

func run(ctx context.Context, args []string) (code int) {
	// The recover of last resort. check.runOne catches a panic in one
	// checker, internal/core/contain.go catches one in a fix — both scoped
	// on purpose, so the rest of a scan or a batch keeps going. This is
	// everything else: a bug in flag parsing, in the TUI's rendering, in
	// dispatch itself. Without it, that bug printed a raw Go stack straight
	// to a terminal that then scrolled it away, which is exactly the "bug
	// report hostveil wants back" internal/core/contain.go already talks
	// about, with no way for anyone to give it one.
	//
	// debug.Stack() runs here, directly in the recover, not inside
	// reportCrash — a stack captured one call further down would start from
	// reportCrash's own frame instead of the one that actually panicked.
	defer func() {
		if r := recover(); r != nil {
			code = reportCrash(args, r, debug.Stack())
		}
	}()

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
	case "export":
		return cmdExport(ctx, args)
	case "rollback":
		return cmdRollback(ctx, args)
	case "history":
		return cmdHistory(ctx, args)
	case "diagnostics":
		return cmdDiagnostics(ctx, args)
	case "update":
		return cmdUpdate(ctx, args)
	case "uninstall":
		return cmdUninstall(ctx, args)
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
  hostveil fix --all --review    ...and the Review ones, through their first
                                 alternative, after reading what they are
  hostveil explain <id> [flags]  Explain a finding (optionally via AI)
  hostveil export --format FMT   Export the scan report: json, sarif, markdown,
                                 docx, or pdf (see Export flags below)
  hostveil serve [flags]         Serve the localhost web dashboard (alias: web)
  hostveil rollback <id> [flags] Undo a previously applied fix
  hostveil history [--scans]     List applied fixes and their rollback IDs;
                                 --scans lists the score of every saved scan
  hostveil diagnostics [flags]   Collect version/OS/crash/scan info into one
                                 file to attach to a bug report by hand
  hostveil update [flags]        Update hostveil to the latest release
  hostveil uninstall [--yes]     Remove hostveil, keeping its saved state
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

Export flags:
  --format FMT    json, sarif, markdown, docx, or pdf (required). json and
                  sarif are byte-identical to scan --json/--sarif. markdown,
                  docx, and pdf explain each finding and its fix in plain
                  language, for a person rather than another program.
  --output FILE   Write to FILE instead of stdout; required for docx/pdf,
                  since a terminal has no sensible way to show them
  --only LIST     Scan only these domains (comma-separated)
  --skip LIST     Scan every domain except these (comma-separated)

Fix flags:
  --all           Apply every safe (Auto) fix; Review and Manual are left alone
  --review        With --all, apply the Review fixes too, each through its
                  first alternative. Manual is still left alone.
  --service NAME  Disambiguate a finding that affects multiple services
  --action N      For Review fixes, pick alternative N (0-based)
  --yes           Apply without an interactive confirmation

Update and uninstall flags:
  --check         update only: report whether a newer release exists and stop.
                  Exit 10 means one is available, so a cron job can act on it.
  --yes           Apply without an interactive confirmation

Explain flags:
  --service NAME  Disambiguate a finding that affects multiple services
  --ai            Add a plain-language AI explanation. Ollama (local) by
                  default; set HOSTVEIL_AI_PROVIDER=anthropic or openai to
                  use an external API instead. See Environment below.

Rollback flags:
  --force         Restore even if the file changed after the fix was applied.
                  Rollback keeps no backup of its own, so it declines by
                  default rather than discard those edits.

Diagnostics flags:
  --trace FILE    Attach a command trace produced with HOSTVEIL_DEBUG=1
  --unredacted    Skip redacting IPs and home-directory usernames (local
                  use only)
  --output FILE   Write the report to FILE instead of printing it

TUI and dashboard flags:
  --theme NAME    Color theme: onedark (default), gruvbox, nord,
                  catppuccin, tokyonight. The TUI's picker (press t) remembers
                  your choice; --theme and HOSTVEIL_THEME override it.
  --glyphs NAME   Symbol set for status markers: plain (default) or nerd.
                  nerd draws them from a patched Nerd Font; a terminal cannot
                  be asked what font it has, so this is opt-in. Also on scan,
                  and settable once with HOSTVEIL_GLYPHS.
  --layout NAME   Screen arrangement for tui and serve: console (default),
                  split, triage, railverdict, lanes, inline. The TUI's picker
                  (press l) remembers your choice; --layout and
                  HOSTVEIL_LAYOUT override it.
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
  hostveil update --check adds 10: a newer release is available. Without
  --check, update and every other command exit 0 on success, 1 on failure,
  and 2 on a usage error. fix --all exits 1 if any fix failed or the batch
  was interrupted.

Environment:
  HOSTVEIL_DEBUG=1     Trace every command hostveil runs against the host, to
                       stderr: what ran, how long it took, and whether it
                       failed. This is what to attach to a bug report about a
                       domain being skipped or a check reporting the wrong
                       thing. Command output is deliberately not logged — it
                       routinely contains environment variables.
  HOSTVEIL_NO_SUDO=1   Never re-exec under sudo (for scripts and CI)
  HOSTVEIL_NO_UPDATE_CHECK
                       Set to any value and hostveil never contacts GitHub on
                       its own. Without it, scan, tui and serve refresh a
                       cached answer to "is there a newer release" once a day.
  HOSTVEIL_THEME=NAME  Color theme for the TUI and the dashboard
  HOSTVEIL_GLYPHS=SET  Symbol set for the TUI and scan: plain or nerd
  HOSTVEIL_LAYOUT=NAME Screen arrangement for the TUI and the dashboard
  NO_COLOR=1           Disable colored output

  HOSTVEIL_AI_PROVIDER=NAME    Which AI backend 'explain --ai' and the AI
                               buttons use: ollama (default — local, nothing
                               leaves the host), anthropic (the Claude API),
                               or openai (any vendor speaking the OpenAI
                               chat-completions shape: OpenAI itself,
                               OpenRouter, Groq, Together, ...).
  HOSTVEIL_OLLAMA_HOST=URL     provider=ollama: where the server listens
                               (default http://127.0.0.1:11434)
  HOSTVEIL_OLLAMA_MODEL=NAME   provider=ollama: which model to ask
                               (default llama3.2)
  ANTHROPIC_API_KEY=KEY        provider=anthropic: the Claude API key — the
                               same variable every Anthropic tool reads
  HOSTVEIL_ANTHROPIC_MODEL=NAME
                               provider=anthropic: which model to ask
                               (default claude-opus-5)
  HOSTVEIL_OPENAI_BASE_URL=URL provider=openai: the API origin
                               (default https://api.openai.com/v1)
  HOSTVEIL_OPENAI_API_KEY=KEY  provider=openai: the API key
  HOSTVEIL_OPENAI_MODEL=NAME   provider=openai: which model to ask —
                               required; there is no cross-vendor default
  All of the above are advisory-only: they affect 'explain --ai' and the AI
  buttons in the TUI and dashboard, and nothing else. No score, finding, or
  fix depends on a model being reachable, and only a finding's title,
  description, suggested fix, and service name are ever sent to it — never
  raw evidence.
`)
}
