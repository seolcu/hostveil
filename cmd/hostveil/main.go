package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/lynis"
	"github.com/seolcu/hostveil/internal/trivy"
	"github.com/seolcu/hostveil/internal/tui"
	"github.com/seolcu/hostveil/internal/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "hostveil: error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "setup":
			return runSetup()
		case "update", "upgrade":
			ensureSudo()
			return runUpdate()
		case "serve", "web":
			ensureSudo()
			return runServe(os.Args[2:])
		case "--help", "-h":
			printHelp()
			return nil
		case "--version", "-v":
			fmt.Println("hostveil", tui.Version)
			return nil
		}
	}

	ensureSudo()

	if !hasFlag("--no-update") {
		checkUpdate()
	}

	result, err := scanHost()
	if err != nil {
		return err
	}

	fmt.Println("  Starting TUI...")
	fmt.Println()

	p := tea.NewProgram(tui.NewApp(result))
	_, err = p.Run()
	return err
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "127.0.0.1:8787", "address to serve the web UI on")
	noUpdate := fs.Bool("no-update", false, "skip update check on startup")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*noUpdate && !hasFlag("--no-update") {
		checkUpdate()
	}

	result, err := scanHost()
	if err != nil {
		return err
	}

	fmt.Printf("  Starting Web UI at http://%s\n", *addr)
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()

	return web.Serve(web.Options{Addr: *addr, Result: result})
}

func scanHost() (*domain.ScanResult, error) {

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
			fmt.Println("  • Trivy: not found (run 'hostveil setup')")
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
			fmt.Println("  • Lynis: not found (run 'hostveil setup')")
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

	return result, nil
}

func runSetup() error {
	fmt.Println("  hostveil setup — installing dependencies")
	fmt.Println()
	cmd := exec.Command("bash", "-c",
		"curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runUpdate() error {
	fmt.Print("  hostveil update: checking latest version...")

	resp, err := http.Get("https://api.github.com/repos/seolcu/hostveil/releases/latest")
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release info: %w", err)
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	fmt.Printf(" %s\n", latest)

	if latest == strings.TrimPrefix(tui.Version, "v") {
		fmt.Println("  Already up to date.")
		return nil
	}

	arch := runtime.GOARCH
	if arch == "x86_64" {
		arch = "amd64"
	}
	url := fmt.Sprintf("https://github.com/seolcu/hostveil/releases/download/v%s/hostveil-%s-%s.tar.gz",
		latest, runtime.GOOS, arch)

	fmt.Printf("  Downloading hostveil %s...\n", latest)
	resp, err = http.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	tmpFile := "/tmp/hostveil.tar.gz"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()

	exec.Command("tar", "xzf", tmpFile, "-C", "/tmp").Run()
	if err := exec.Command("install", "-m", "755", "/tmp/hostveil", "/usr/bin/hostveil").Run(); err != nil {
		return fmt.Errorf("install failed: %w", err)
	}
	os.Remove(tmpFile)
	fmt.Println("  Updated to v" + latest)
	return nil
}

func checkUpdate() {
	resp, err := http.Get("https://api.github.com/repos/seolcu/hostveil/releases/latest")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(tui.Version, "v")
	if latest != current {
		fmt.Printf("\n  Update available: v%s (current: v%s)\n", latest, current)
		fmt.Println("  Run 'hostveil update' to upgrade.")
		fmt.Println("  Use 'hostveil --no-update' to skip this check.")
		fmt.Println()
	}
}

func printHelp() {
	fmt.Println(`hostveil — Linux self-hosting security scanner

Usage:
  hostveil                    Scan and open TUI
  hostveil serve              Scan and serve Web UI on 127.0.0.1:8787
  hostveil web                Alias for serve
  hostveil serve --addr ADDR  Serve Web UI on a custom address
  hostveil setup              Install dependencies (trivy, lynis)
  hostveil update             Update to the latest version
  hostveil --no-update        Skip update check on startup
  hostveil --version          Show version
  hostveil --help             Show this help`)
}

func hasFlag(name string) bool {
	for _, a := range os.Args {
		if a == name {
			return true
		}
	}
	return false
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
