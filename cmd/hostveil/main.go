package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/seolcu/hostveil/internal/config"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/scanner"
	"github.com/seolcu/hostveil/internal/tui"
	"github.com/seolcu/hostveil/internal/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse()
	if err != nil {
		return err
	}

	// Web mode: serve the TUI via ttyd
	if cfg.Serve {
		return web.Serve(cfg)
	}

	result, err := scanner.Run(scanner.Config{
		UserMode: cfg.UserMode,
	})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	return runTUI(result)
}

func runTUI(result *domain.ScanResult) error {
	p := tea.NewProgram(tui.NewApp(result), tea.WithAltScreen())
	_, err := p.Run()
	if err == tea.ErrProgramKilled {
		return nil // ttyd lifecycle (WebSocket reconnect), not an error
	}
	return err
}
