package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdExplain(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	var (
		service string
		useAI   bool
		only    string
		skip    string
	)
	fs.StringVar(&service, "service", "", "disambiguate a finding by service name")
	fs.BoolVar(&useAI, "ai", false, "add an advisory AI explanation (Ollama by default; see HOSTVEIL_AI_PROVIDER)")
	fs.StringVar(&only, "only", "", "with no finding ID: scan only these domains (comma-separated)")
	fs.StringVar(&skip, "skip", "", "with no finding ID: scan every domain except these (comma-separated)")

	var findingID string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		findingID, args = args[0], args[1:]
	}
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}
	if findingID == "" {
		return explainAll(ctx, useAI, only, skip)
	}

	engine := newEngineWithAI(useAI)
	report := engine.Scan(ctx, nil)
	finding, ok := findFinding(report, findingID, service)
	if !ok {
		fmt.Fprintf(os.Stderr, "hostveil: no active finding %q%s\n", findingID, serviceSuffix(service))
		return 1
	}

	exp := engine.Explain(ctx, finding, useAI)
	fmt.Println(exp.Plain)
	if useAI {
		fmt.Println()
		switch {
		case exp.AI != "":
			fmt.Println("── AI explanation (advisory) ──")
			fmt.Println(exp.AI)
		case exp.AIError != "":
			fmt.Println("(AI explanation unavailable: " + exp.AIError + ")")
		}
	}
	return 0
}

// explainAll is explain with no finding ID: every finding with a registered
// fix, with what applying it would get and cost, and with --ai a verdict per
// finding weighed against the saved host description.
func explainAll(ctx context.Context, useAI bool, only, skip string) int {
	scanOpts, errMsg := scanSelection(only, skip)
	if errMsg != "" {
		fmt.Fprintln(os.Stderr, "hostveil:", errMsg)
		return 2
	}

	engine := newEngineWithAI(useAI)
	startUpdateCheck(ctx)
	report := scanWithProgress(ctx, engine, scanOpts)

	adv := engine.Advise(ctx, report.Findings, useAI)
	fmt.Println(adv.Plain)
	if useAI {
		fmt.Println()
		switch {
		case adv.AI != "":
			fmt.Println("── AI verdict (advisory) ──")
			fmt.Println(adv.AI)
		case adv.AIError != "":
			fmt.Println("(AI verdict unavailable: " + adv.AIError + ")")
		}
	}
	return 0
}
