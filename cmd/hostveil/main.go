package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"

	tea "charm.land/bubbletea/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/tui"
)

var httpClient = &http.Client{Timeout: domain.HTTPClientTimeout}

var checkLatestURL = "https://api.github.com/repos/seolcu/hostveil/releases/latest"
var installerURL = "https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh"
var installerChecksumURL = "https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh.sha256"

// releaseDownloadBaseURL is the base for versioned release asset
// downloads (the archive and its checksums file). Overridden in tests.
var releaseDownloadBaseURL = "https://github.com/seolcu/hostveil/releases/download"

// hostveilInstallPath is where `hostveil update` installs the new binary.
// Overridden in tests so runUpdate never touches the real system path.
var hostveilInstallPath = "/usr/bin/hostveil"

func newFixRegistry() *fix.Registry {
	r := fix.New()
	fix.RegisterAll(r)
	return r
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "hostveil: error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "setup":
			return runSetup()
		case "update", "upgrade":
			ensureSudo()
			return runUpdate()
		case "serve", "web":
			if hasFlag(os.Args, "--fixture") || hasFixtureWithValue(os.Args) {
				return runServe(os.Args[2:])
			}
			ensureSudo()
			return runServe(os.Args[2:])
		case "tui-web":
			ensureSudo()
			return runTUIWeb(os.Args[2:])
		case "history":
			return runHistory(os.Args[2:])
		case "rollback":
			ensureSudo()
			return runRollback(os.Args[2:])
		case "--help", "-h":
			printHelp()
			return nil
		case "--version", "-v":
			fmt.Println("hostveil", tui.Version)
			return nil
		default:
			fmt.Fprintf(os.Stderr, "hostveil: unknown subcommand %q\n", os.Args[1])
			fmt.Fprintln(os.Stderr)
			printHelp()
			return fmt.Errorf("unknown subcommand: %s", os.Args[1])
		}
	}

	ensureSudo()
	noUpdate := hasFlag(os.Args, "--no-update")
	noScan := hasFlag(os.Args, "--no-scan")

	reg := newFixRegistry()
	live := domain.NewScanProgress(noUpdate)
	live.Hostname, _ = os.Hostname()
	live.LocalIP = localIP()

	m := tui.NewApp(live, reg)
	p := tea.NewProgram(m)
	m.SetProgram(func(msg tea.Msg) { p.Send(msg) })

	if !noUpdate {
		go runUpdateCheckBackground(live)
	}
	if !noScan {
		launchScanners(live, reg)
	} else {
		skipScanners(live)
	}

	_, err := p.Run()
	return err
}

func printHelp() {
	fmt.Println(helpText())
}

func helpText() string {
	return `hostveil finds security problems on your self-hosted Docker host, and fixes them.

Run:
  hostveil            Scan everything, open the terminal UI
  hostveil serve      Scan everything, serve the Web UI (127.0.0.1:8787)
  hostveil tui-web    TUI and Web UI at the same time
  hostveil web        Alias for serve
  hostveil --no-scan  Open the TUI immediately, skip scanning

Configure:
  hostveil serve --addr ADDR                      Serve on a custom address
  hostveil serve --cert-file CERT --key-file KEY  Serve over HTTPS
  hostveil serve --fixture FILE                   Serve fixture data (E2E testing)

Maintain:
  hostveil setup        Install or update trivy/lynis
  hostveil update       Upgrade hostveil to the latest release
  hostveil --no-update  Skip the startup update check

History and rollback:
  hostveil history          List past fixes, each with a restore point
  hostveil history show ID  Show one checkpoint's backed-up files and diff
  hostveil history --scans  List past scans with the score change
  hostveil rollback ID      Undo a fix, restoring the files it changed

  hostveil --version  Show installed version
  hostveil --help     Show this help`
}

func ensureSudo() {
	if os.Geteuid() == 0 {
		return
	}
	cmd := exec.Command("sudo", os.Args...) //nolint:gosec // required for root re-exec
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintln(os.Stderr, "hostveil requires root access.")
			os.Exit(1)
		}
	}
	os.Exit(exitCode)
}
