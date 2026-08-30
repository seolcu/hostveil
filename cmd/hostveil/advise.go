package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

func cmdAdvise(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("advise", flag.ContinueOnError)
	var (
		useAI bool
		only  string
		skip  string
	)
	fs.BoolVar(&useAI, "ai", false, "add an AI verdict per finding (Ollama by default; see HOSTVEIL_AI_PROVIDER)")
	fs.StringVar(&only, "only", "", "scan only these domains (comma-separated)")
	fs.StringVar(&skip, "skip", "", "scan every domain except these (comma-separated)")
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}
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
