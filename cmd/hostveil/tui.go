package main

import (
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/ui/tui"
)

func cmdTUI(_ []string) int {
	if !isInteractive() {
		fmt.Fprintln(os.Stderr, "hostveil: the TUI requires an interactive terminal; use `hostveil scan` instead.")
		return 0
	}
	if err := tui.Run(buildEngine()); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	return 0
}

// isInteractive reports whether both stdin and stdout are terminals.
func isInteractive() bool {
	return isCharDevice(os.Stdin) && isCharDevice(os.Stdout)
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
