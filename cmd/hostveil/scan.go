package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/model"
)

func cmdScan(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		jsonOut  bool
		sarifOut bool
		verbose  bool
		noColor  bool
		output   string
		only     string
		skip     string
	)
	fs.BoolVar(&jsonOut, "json", false, "output the report as JSON")
	fs.BoolVar(&sarifOut, "sarif", false, "output the report as SARIF 2.1.0")
	fs.BoolVar(&verbose, "verbose", false, "show descriptions and fix guidance")
	fs.BoolVar(&verbose, "v", false, "show descriptions and fix guidance (shorthand)")
	fs.BoolVar(&noColor, "no-color", false, "disable colored output")
	fs.StringVar(&output, "output", "", "write the report to a file instead of stdout")
	fs.StringVar(&only, "only", "", "scan only these domains (comma-separated); a partial scan is not saved as the last-scan baseline")
	fs.StringVar(&skip, "skip", "", "scan every domain except these (comma-separated); a partial scan is not saved as the last-scan baseline")
	glyphSet := fs.String("glyphs", "", "symbol set ("+glyphList()+")")
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}
	if jsonOut && sarifOut {
		fmt.Fprintln(os.Stderr, "hostveil: --json and --sarif are mutually exclusive")
		return 2
	}
	scanOpts, errMsg := scanSelection(only, skip)
	if errMsg != "" {
		fmt.Fprintln(os.Stderr, "hostveil:", errMsg)
		return 2
	}
	gl, err := resolveGlyphs(*glyphSet)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 2
	}

	engine := newEngine()
	report := scanWithProgress(ctx, engine, scanOpts)

	var rendered string
	switch {
	case jsonOut:
		out, err := clirender.JSON(report)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		rendered = out + "\n"
	case sarifOut:
		out, err := clirender.SARIF(report, version)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		rendered = out + "\n"
	default:
		// A report written to a file is read later, without the terminal it
		// was produced on — never color it.
		opts := clirender.Options{
			Color: output == "" && !noColor && colorEnabled(), Verbose: verbose, Glyphs: gl,
		}
		rendered = clirender.Text(report, opts)
		if delta := engine.LastDelta(); delta.HasChanges() {
			rendered += clirender.DeltaSummary(delta, opts)
		}
	}

	if output != "" {
		if err := os.WriteFile(output, []byte(rendered), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
	} else {
		fmt.Print(rendered)
	}
	// The exit code is the CI contract and does not vary by output format
	// or destination.
	return exitCode(report)
}

// scanWithProgress runs a scan, showing which domains are still working
// while it does.
//
// The display goes to stderr and only when stderr is a terminal, so `--json`,
// a redirect, and a cron run all produce exactly the bytes they did before.
// When there is nowhere useful to draw, the scan runs with a nil channel and
// no goroutine — the same path as before this existed.
func scanWithProgress(ctx context.Context, engine *core.Engine, opts core.ScanOptions) model.Report {
	if !isCharDevice(os.Stderr) {
		return engine.ScanWith(ctx, nil, opts)
	}

	events := make(chan model.ScanEvent, clirender.ProgressBufferSize)
	done := make(chan struct{})
	go func() {
		defer close(done)
		clirender.Progress(os.Stderr, events)
	}()

	report := engine.ScanWith(ctx, events, opts)
	close(events)
	<-done // let the renderer clear its line before the report is printed
	return report
}

// scanSelection turns --only/--skip into ScanOptions, validating domain
// names against the real source set so a typo is a usage error naming the
// valid choices rather than a silently empty scan.
func scanSelection(only, skip string) (core.ScanOptions, string) {
	if only != "" && skip != "" {
		return core.ScanOptions{}, "--only and --skip are mutually exclusive"
	}
	list := only
	if skip != "" {
		list = skip
	}
	if list == "" {
		return core.ScanOptions{}, ""
	}

	byName := map[string]model.Source{}
	var names []string
	for _, s := range model.AllSources() {
		byName[s.String()] = s
		names = append(names, s.String())
	}

	selected := map[model.Source]bool{}
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		src, ok := byName[name]
		if !ok {
			return core.ScanOptions{}, fmt.Sprintf("unknown domain %q (valid: %s)", name, strings.Join(names, ", "))
		}
		selected[src] = true
	}
	if len(selected) == 0 {
		return core.ScanOptions{}, "no domains named"
	}

	var out []model.Source
	for _, s := range model.AllSources() {
		if selected[s] == (only != "") {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return core.ScanOptions{}, "--skip removes every domain; nothing would be scanned"
	}
	return core.ScanOptions{Only: out}, ""
}

// Exit codes for scan. These are the CI and cron contract, so they are
// named rather than written as bare integers at the return sites.
const (
	exitClean      = 0 // the scan ran and found nothing serious
	exitFindings   = 1 // unfixed Exposed findings
	exitIncomplete = 3 // a domain failed outright; the result describes less than the host
)

// exitCode is what a CI or cron gate reads.
//
// Findings come first: an unfixed Exposed finding is the answer the gate
// exists for, and it stays 1 whatever else happened.
//
// Exposed is exactly the set the old Critical and High were together — both
// folded into it when the scale went to three levels — so a pipeline that has
// been gating on this code sees no change.
//
// A domain in ScanError is the second answer, and it used to have none.
// The code was derived from findings alone, and a failed domain contributes
// zero findings — so an unreachable Docker socket silenced the two heaviest
// axes and the pipeline saw exit 0. A blind scan and a clean host were
// indistinguishable to the one consumer that cannot look at the output.
//
// Skipped and Degraded deliberately do not qualify. Skipped is the ordinary
// state of a host that has no Docker or no Trivy, and failing every such
// pipeline would train people to ignore the code. Degraded means the checker
// covered part of its ground and said so, and those findings are real and
// scored; it is reported in the output, not in the exit status.
func exitCode(r model.Report) int {
	for _, f := range r.Findings {
		if f.Fixed {
			continue
		}
		if f.Severity == model.SeverityExposed {
			return exitFindings
		}
	}
	for _, d := range r.Domains {
		if d.State == model.ScanError {
			return exitIncomplete
		}
	}
	return exitClean
}

// colorEnabled reports whether to emit ANSI color: honored only when
// stdout is a terminal and NO_COLOR is unset.
func colorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
