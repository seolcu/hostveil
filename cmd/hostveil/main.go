package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/lynis"
	"github.com/seolcu/hostveil/internal/trivy"
	"github.com/seolcu/hostveil/internal/tui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ensureSudo()

	fmt.Println()
	fmt.Println("  hostveil — scanning")
	fmt.Println()

	var wg sync.WaitGroup
	var trivyFindings, lynisFindings []domain.Finding
	var trivyErr, lynisErr error

	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := exec.LookPath("trivy"); err != nil {
			fmt.Println("  • Trivy: not found (install via: apt install trivy)")
			return
		}
		fmt.Print("  • Trivy: scanning compose projects...")
		trivyFindings, trivyErr = trivy.ScanAll()
		if trivyErr != nil {
			fmt.Printf(" warning: %v", trivyErr)
		}
		fmt.Println(" done")
	}()

	go func() {
		defer wg.Done()
		if _, err := exec.LookPath("lynis"); err != nil {
			fmt.Println("  • Lynis: not found (install via: apt install lynis)")
			return
		}
		fmt.Print("  • Lynis: auditing system hardening...")
		lynisFindings, lynisErr = lynis.Scan()
		if lynisErr != nil {
			fmt.Printf(" warning: %v", lynisErr)
		}
		fmt.Println(" done")
	}()

	wg.Wait()

	all := append(trivyFindings, lynisFindings...)
	result := &domain.ScanResult{
		Findings: all,
		Score:    calculateScore(all),
	}

	fmt.Printf("  • Found %d findings (%d fixable)\n", len(all), countFixable(all))
	fmt.Println()
	fmt.Println("  Starting TUI...")
	fmt.Println()

	p := tea.NewProgram(tui.NewApp(result), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func calculateScore(findings []domain.Finding) uint8 {
	if len(findings) == 0 {
		return 100
	}
	total := 0
	for _, f := range findings {
		switch f.Severity {
		case domain.SeverityCritical:
			total += 4
		case domain.SeverityHigh:
			total += 3
		case domain.SeverityMedium:
			total += 2
		case domain.SeverityLow:
			total += 1
		}
	}
	score := 100 - total*5
	if score < 0 {
		return 0
	}
	return uint8(score)
}

func countFixable(findings []domain.Finding) int {
	n := 0
	for _, f := range findings {
		if f.IsFixable() {
			n++
		}
	}
	return n
}

func ensureSudo() {
	if os.Geteuid() == 0 {
		return
	}
	cmd := exec.Command("sudo", os.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil requires root access.")
		os.Exit(1)
	}
	os.Exit(0)
}
