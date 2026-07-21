package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	var (
		service string
		useAI   bool
	)
	fs.StringVar(&service, "service", "", "disambiguate a finding by service name")
	fs.BoolVar(&useAI, "ai", false, "add an advisory explanation from a local LLM (Ollama)")

	var findingID string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		findingID, args = args[0], args[1:]
	}
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}
	if findingID == "" {
		fmt.Fprintln(os.Stderr, "usage: hostveil explain <finding-id> [--service NAME] [--ai]")
		return 2
	}

	engine := buildEngineWithAI(useAI)
	report := engine.Scan(context.Background(), nil)
	finding, ok := findFinding(report, findingID, service)
	if !ok {
		fmt.Fprintf(os.Stderr, "hostveil: no active finding %q%s\n", findingID, serviceSuffix(service))
		return 1
	}

	exp := engine.Explain(context.Background(), finding, useAI)
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
