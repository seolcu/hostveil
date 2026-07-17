// Command hostveil is a guided hardening tool for self-hosted Linux
// servers: it scans the host for the security mistakes most likely to get
// a non-expert self-hoster hacked, explains them in plain language, and
// (in later phases) fixes them safely with preview, backup, and rollback.
package main

import (
	"fmt"
	"os"
	"strings"
)

// version is the build version, overridden via -ldflags at release time.
var version = "v3-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := "scan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "scan":
		return cmdScan(args)
	case "version", "--version", "-v":
		fmt.Println("hostveil", version)
		return 0
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "hostveil: unknown command %q\n\n", cmd)
		printUsage(os.Stderr)
		return 2
	}
}

func printUsage(w *os.File) {
	fmt.Fprint(w, `hostveil — guided hardening for self-hosted Linux servers

Usage:
  hostveil [scan] [flags]   Scan the host and report security findings
  hostveil version          Print the version
  hostveil help             Show this help

Scan flags:
  -v, --verbose   Show each finding's description and fix guidance
  --json          Output the report as JSON
  --no-color      Disable colored output
`)
}
