package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/seolcu/hostveil/internal/config"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/scanner"
	"github.com/seolcu/hostveil/internal/tui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if _, err := config.Parse(); err != nil {
		return err
	}

	result, err := scanner.Run(scanner.Config{})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	return runTUI(result)
}

func runTUI(result *domain.ScanResult) error {
	p := tea.NewProgram(tui.NewApp(result), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
