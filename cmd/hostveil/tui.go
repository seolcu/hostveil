package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/ui/theme"
	"github.com/seolcu/hostveil/internal/ui/tui"
)

func cmdTUI(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	themeID := fs.String("theme", "", "color theme ("+themeList()+")")
	layoutID := fs.String("layout", "", "screen arrangement ("+strings.Join(tui.LayoutIDs(), ", ")+")")
	glyphSet := fs.String("glyphs", "", "symbol set ("+glyphList()+")")
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}
	lay, err := resolveLayout(*layoutID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 2
	}

	t, err := resolveTheme(*themeID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 2
	}
	gl, err := resolveGlyphs(*glyphSet)
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
	layOpts := tui.LayoutOpts{Initial: lay.ID, Save: saveLayoutPref}
	// The advisory AI provider is wired in for the detail view's `e` key.
	// Construction does no I/O; with no Ollama reachable the view shows a
	// one-line note instead.
	if err := tui.Run(ctx, buildEngineWithAI(true), tui.Opts{Theme: opts, Layout: layOpts, Glyphs: gl}); err != nil {
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
