package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/ui/theme"
	"github.com/seolcu/hostveil/internal/ui/tui"
)

func cmdTUI(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	themeID := fs.String("theme", "", "color theme ("+themeList()+")")
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}

	t, err := resolveTheme(*themeID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 2
	}

	if !isInteractive() {
		fmt.Fprintln(os.Stderr, "hostveil: the TUI requires an interactive terminal; use `hostveil scan` instead.")
		return 0
	}
	dir := stateDir()
	opts := tui.ThemeOpts{
		Initial: t,
		Save:    func(id string) error { return theme.Save(dir, id) },
	}
	// The advisory AI provider is wired in for the detail view's `e` key.
	// Construction does no I/O; with no Ollama reachable the view shows a
	// one-line note instead.
	if err := tui.Run(ctx, buildEngineWithAI(true), opts); err != nil {
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
