package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdAIContext(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("ai-context", flag.ContinueOnError)
	var clear bool
	fs.BoolVar(&clear, "clear", false, "remove the saved host description")

	var text string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		text, args = args[0], args[1:]
	}
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}
	if clear && text != "" {
		fmt.Fprintln(os.Stderr, "hostveil: --clear takes no text")
		return 2
	}

	engine := newEngine()
	switch {
	case clear:
		if err := engine.SetAIContext(""); err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		fmt.Println("Cleared.")
	case text != "":
		if err := engine.SetAIContext(text); err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		fmt.Println("Saved. Every AI explanation and `hostveil advise` will use this from now on:")
		fmt.Println("  " + text)
	default:
		got := engine.AIContext()
		if got == "" {
			fmt.Println("(not set)")
			fmt.Println("Set one with: hostveil ai-context \"a short description of this host\"")
		} else {
			fmt.Println(got)
		}
	}
	return 0
}
