package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/tui"
)

// cmdFleet scans several hosts over SSH and lays their scores side by side.
//
// It is the one command that must not elevate. It reaches the hosts with the
// invoking user's SSH keys, agent and ~/.ssh/config, and sudo's env_reset
// drops SSH_AUTH_SOCK and HOME along with everything else — so an elevated
// fleet scan would be root trying to log in as root with nothing to log in
// with. needsRoot says no for it, and clidocs_test holds that to a reason.
func cmdFleet(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "output every host's report as JSON")
	sudo := fs.Bool("sudo", false, "run the remote scan as `sudo -n hostveil scan` (needs passwordless sudo there)")
	parallel := fs.Int("parallel", 4, "how many hosts to scan at once")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for one host")
	useTUI := fs.Bool("tui", false, "show the result in the terminal UI")
	noColor := fs.Bool("no-color", false, "disable colored output")
	themeID := fs.String("theme", "", "color theme for --tui ("+themeList()+")")
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}
	hosts := fs.Args()
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "hostveil fleet: name at least one host, as you would to ssh (user@host, or an alias from ~/.ssh/config)")
		return 2
	}
	for _, h := range hosts {
		if err := core.ValidateFleetHost(h); err != nil {
			fmt.Fprintln(os.Stderr, "hostveil fleet:", err)
			return 2
		}
	}
	if *jsonOut && *useTUI {
		fmt.Fprintln(os.Stderr, "hostveil fleet: --json and --tui are mutually exclusive")
		return 2
	}
	opts := core.FleetOptions{Sudo: *sudo, Parallel: *parallel, Timeout: *timeout}
	engine := buildEngine()

	if *useTUI {
		if !isInteractive() {
			fmt.Fprintln(os.Stderr, "hostveil fleet: --tui requires an interactive terminal")
			return 2
		}
		t, err := resolveTheme(*themeID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 2
		}
		if err := tui.RunFleet(ctx, engine, hosts, tui.FleetOpts{Theme: t, Fleet: opts}); err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		return 0
	}

	if !*jsonOut && isInteractive() {
		fmt.Fprintf(os.Stderr, "Scanning %d host(s) over SSH…\n", len(hosts))
	}
	f := engine.Fleet(ctx, hosts, opts)
	if *jsonOut {
		out, err := clirender.FleetJSON(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		fmt.Println(out)
	} else {
		fmt.Print(clirender.Fleet(f, clirender.Options{Color: !*noColor && colorEnabled()}))
	}
	return fleetExitCode(f)
}

// fleetExitCode extends scan's CI contract across hosts, in scan's own order:
// 1 when any host has an unfixed High finding — the answer the gate exists
// for, whatever else happened — otherwise 3 when any host could not be
// scanned or had a domain fail outright, since then the result describes less
// than the fleet. A host nobody could reach is the fleet's version of a
// failed domain, and a pipeline must not read it as a clean one.
func fleetExitCode(f model.Fleet) int {
	incomplete := false
	for _, e := range f.Hosts {
		if e.Report == nil {
			incomplete = true
			continue
		}
		switch exitCode(*e.Report) {
		case exitFindings:
			return exitFindings
		case exitIncomplete:
			incomplete = true
		}
	}
	if incomplete {
		return exitIncomplete
	}
	return exitClean
}
