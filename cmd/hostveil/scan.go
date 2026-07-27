package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/model"
)

func cmdScan(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		jsonOut bool
		verbose bool
		noColor bool
	)
	fs.BoolVar(&jsonOut, "json", false, "output the report as JSON")
	fs.BoolVar(&verbose, "verbose", false, "show descriptions and fix guidance")
	fs.BoolVar(&verbose, "v", false, "show descriptions and fix guidance (shorthand)")
	fs.BoolVar(&noColor, "no-color", false, "disable colored output")
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}

	engine := buildEngine()
	report := scanWithProgress(ctx, engine)

	if jsonOut {
		out, err := clirender.JSON(report)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		fmt.Println(out)
		return exitCode(report)
	}

	opts := clirender.Options{Color: !noColor && colorEnabled(), Verbose: verbose}
	fmt.Print(clirender.Text(report, opts))
	if delta := engine.LastDelta(); delta.HasChanges() {
		fmt.Print(clirender.DeltaSummary(delta))
	}
	return exitCode(report)
}

// scanWithProgress runs a scan, showing which domains are still working
// while it does.
//
// The display goes to stderr and only when stderr is a terminal, so `--json`,
// a redirect, and a cron run all produce exactly the bytes they did before.
// When there is nowhere useful to draw, the scan runs with a nil channel and
// no goroutine — the same path as before this existed.
func scanWithProgress(ctx context.Context, engine *core.Engine) model.Report {
	if !isCharDevice(os.Stderr) {
		return engine.Scan(ctx, nil)
	}

	events := make(chan model.ScanEvent, clirender.ProgressBufferSize)
	done := make(chan struct{})
	go func() {
		defer close(done)
		clirender.Progress(os.Stderr, events)
	}()

	report := engine.Scan(ctx, events)
	close(events)
	<-done // let the renderer clear its line before the report is printed
	return report
}

// Exit codes for scan. These are the CI and cron contract, so they are
// named rather than written as bare integers at the return sites.
const (
	exitClean      = 0 // the scan ran and found nothing serious
	exitFindings   = 1 // unfixed Critical or High findings
	exitIncomplete = 3 // a domain failed outright; the result describes less than the host
)

// exitCode is what a CI or cron gate reads.
//
// Findings come first: an unfixed Critical or High is the answer the gate
// exists for, and it stays 1 whatever else happened.
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
		if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
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
