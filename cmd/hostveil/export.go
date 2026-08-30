package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

func cmdExport(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	var (
		format string
		output string
		only   string
		skip   string
	)
	fs.StringVar(&format, "format", "", "export format: json, sarif, markdown, docx, or pdf (required)")
	fs.StringVar(&output, "output", "", "write to FILE instead of stdout; required for docx/pdf")
	fs.StringVar(&only, "only", "", "scan only these domains (comma-separated); a partial scan is not saved as the last-scan baseline")
	fs.StringVar(&skip, "skip", "", "scan every domain except these (comma-separated); a partial scan is not saved as the last-scan baseline")
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}
	if format == "" {
		fmt.Fprintln(os.Stderr, "hostveil: --format is required (json, sarif, markdown, docx, pdf)")
		return 2
	}
	// Binary formats have no sensible stdout behavior in an interactive
	// terminal or a shell pipeline expecting text — refuse rather than write
	// a .docx/.pdf's raw bytes wherever stdout happens to be redirected.
	if output == "" && (format == "docx" || format == "pdf") {
		fmt.Fprintln(os.Stderr, "hostveil: --output is required for --format "+format)
		return 2
	}
	scanOpts, errMsg := scanSelection(only, skip)
	if errMsg != "" {
		fmt.Fprintln(os.Stderr, "hostveil:", errMsg)
		return 2
	}

	engine := newEngine()
	startUpdateCheck(ctx)
	report := scanWithProgress(ctx, engine, scanOpts)

	data, _, _, err := engine.Export(report, format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 2
	}

	if output != "" {
		if err := writeReport(output, data); err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
	} else {
		fmt.Print(string(data))
		if len(data) > 0 && data[len(data)-1] != '\n' {
			fmt.Println()
		}
	}
	return exitCode(report)
}
