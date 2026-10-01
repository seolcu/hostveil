package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// FleetOptions controls a fleet scan.
type FleetOptions struct {
	// Sudo runs the remote scan as `sudo -n hostveil scan`, for hosts where
	// the account you SSH in as can sudo without a password. Without it the
	// remote scan runs as that account, and the root-only domains report
	// themselves as not audited — which the table shows, not hides.
	Sudo bool
	// Parallel bounds how many hosts are scanned at once. Zero means 4.
	Parallel int
	// Timeout bounds each host. Zero means 10 minutes, which is what a
	// first Trivy run on a host with many images needs.
	Timeout time.Duration
}

// ValidateFleetHost refuses a host argument ssh would read as an option.
//
// ssh parses its arguments before it knows which one is the destination, so
// `-oProxyCommand=…` named as a "host" runs a local command. The argv also
// passes `--` ahead of the host, which is the belt; this is the braces, and
// it is what turns the mistake into an error the operator sees rather than a
// connection that fails in a confusing way.
func ValidateFleetHost(h string) error {
	switch {
	case h == "":
		return errors.New("a host cannot be empty")
	case strings.HasPrefix(h, "-"):
		return fmt.Errorf("%q starts with '-', which ssh would read as an option rather than a host", h)
	case strings.ContainsAny(h, " \t\n"):
		return fmt.Errorf("%q contains whitespace, which no ssh destination does", h)
	}
	return nil
}

// FleetArgv is the ssh command a fleet scan runs for one host. It is exported
// so a test that scripts a fake runner spells it through here rather than
// again by hand — the checktest rule for DockerProbeArgv, for the same reason.
func FleetArgv(host string, sudo bool) []string {
	argv := []string{"ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host}
	if sudo {
		return append(argv, "sudo", "-n", "hostveil", "scan", "--json")
	}
	// HOSTVEIL_NO_SUDO, because the remote hostveil would otherwise try to
	// re-exec itself under sudo, and with BatchMode there is no terminal to
	// type a password into — the scan would fail instead of running
	// unprivileged and saying which domains it could not see.
	return append(argv, "env", "HOSTVEIL_NO_SUDO=1", "hostveil", "scan", "--json")
}

// Fleet scans each host over SSH with the hostveil already installed there,
// and collects the reports side by side.
//
// Nothing is installed, copied or configured on the remote host, and nothing
// here is a service: it is one local process calling `hostveil scan --json`
// over SSH the operator already trusts, which is the whole of what the
// roadmap promised and the line this project will not cross.
//
// The result keeps the order the hosts were named in; Fleet.WorstFirst is
// the order a reader wants.
func (e *Engine) Fleet(ctx context.Context, hosts []string, opts FleetOptions) model.Fleet {
	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 4
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	out := model.Fleet{Hosts: make([]model.FleetEntry, len(hosts))}
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, h := range hosts {
		out.Hosts[i].Host = h
		if err := ValidateFleetHost(h); err != nil {
			out.Hosts[i].Error = err.Error()
			continue
		}
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				out.Hosts[i].Error = "cancelled before it was scanned"
				return
			}
			defer func() { <-sem }()
			hctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			argv := FleetArgv(h, opts.Sudo)
			stdout, err := e.runner.Run(hctx, argv[0], argv[1:]...)
			out.Hosts[i].Report, out.Hosts[i].Error = readFleetAnswer(stdout, err, opts.Sudo)
		}(i, h)
	}
	wg.Wait()
	return out
}

// readFleetAnswer turns one host's ssh result into a report or a reason.
//
// The exit status alone cannot decide it. `hostveil scan` exits 1 when it
// found a High finding and 3 when a domain failed outright, and both of those
// come with a complete report on stdout; ssh passes the remote status through
// unchanged, so 1 means "scanned, and found something" as often as it means
// "sudo refused". The report is tried first, and only a stdout that is not
// one makes the status the answer.
func readFleetAnswer(stdout []byte, err error, sudo bool) (*model.Report, string) {
	var r model.Report
	if len(strings.TrimSpace(string(stdout))) > 0 {
		if jerr := json.Unmarshal(stdout, &r); jerr == nil && len(r.Domains) > 0 {
			return &r, ""
		}
	}
	if err == nil {
		return nil, "answered with something that is not a hostveil report — is `hostveil` on that host a different program?"
	}
	var exitErr *exec.ExitError
	code := -1
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "timed out") || strings.Contains(msg, "deadline"):
		return nil, "the scan did not finish in time"
	case code == 255:
		return nil, "could not connect over SSH: " + trimExit(msg)
	case code == 127:
		return nil, "hostveil is not installed there, or not on the PATH a non-interactive SSH session gets"
	case sudo && strings.Contains(msg, "password is required"):
		// sudo gives this same answer when no rule matches because the
		// binary the rule names is not there, so the message names both.
		return nil, "sudo would not run hostveil without a password there — --sudo needs hostveil installed and allowed by a NOPASSWD rule"
	default:
		return nil, "the remote scan failed: " + trimExit(msg)
	}
}

// trimExit drops Go's "exit status N: " prefix, which says nothing an
// operator can act on, and keeps the stderr line the runner appended.
func trimExit(msg string) string {
	if _, rest, ok := strings.Cut(msg, ": "); ok && strings.HasPrefix(msg, "exit status") {
		return rest
	}
	return msg
}
