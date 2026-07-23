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

// exitCode returns 1 when any unfixed high-or-critical finding was
// detected, so scripts and CI can gate on it; 0 otherwise.
func exitCode(r model.Report) int {
	for _, f := range r.Findings {
		if f.Fixed {
			continue
		}
		if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
			return 1
		}
	}
	return 0
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
