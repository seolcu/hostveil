package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/model"
)

func cmdScan(args []string) int {
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
	if err := fs.Parse(args); err != nil {
		return 2
	}

	report := buildEngine().Scan(context.Background(), nil)

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
	return exitCode(report)
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
