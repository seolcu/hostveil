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
	noUpdate := hasFlag("--no-update")

	live := domain.NewScanProgress(noUpdate)

	notify := func() {}
	m := tui.NewApp(live, noUpdate)
	p := tea.NewProgram(m)
	m.SetProgram(func(msg tea.Msg) { p.Send(msg) })

	if !noUpdate {
		go runUpdateCheckBackground(live, notify)
	}
	go runScanBackground(live, "trivy", notify)
	go runScanBackground(live, "lynis", notify)

	_, err := p.Run()
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

	skipUpdate := *noUpdate || hasFlag("--no-update")
	live := domain.NewScanProgress(skipUpdate)

	if !skipUpdate {
		go runUpdateCheckBackground(live, nil)
	}
	go runScanBackground(live, "trivy", nil)
	go runScanBackground(live, "lynis", nil)

	fmt.Printf("  Starting Web UI at http://%s\n", *addr)
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()

	return web.Serve(web.Options{Addr: *addr, Live: live})
}

func runScanBackground(live *domain.ScanProgress, tool string, notify func()) {
	if _, err := exec.LookPath(tool); err != nil {
		live.SetToolStatus(tool, domain.ToolSkipped, fmt.Sprintf("Not found (run 'hostveil setup')"))
		return
	}

	live.SetToolStatus(tool, domain.ToolRunning, scanningMessage(tool))

	var findings []domain.Finding
	var scanErr error
	switch tool {
	case "trivy":
		findings, scanErr = trivy.ScanAll()
	case "lynis":
		findings, scanErr = lynis.Scan()
	}

	if scanErr != nil {
		live.SetToolStatus(tool, domain.ToolError, fmt.Sprintf("Error: %v", scanErr))
	} else {
		live.SetToolStatus(tool, domain.ToolDone, fmt.Sprintf("Found %d issues", len(findings)))
		live.AddFindings(findings)
	}

	if live.AllToolsDone() {
		live.Finalize()
	}
}

func scanningMessage(tool string) string {
	switch tool {
	case "trivy":
		return "Scanning compose projects..."
	case "lynis":
		return "Auditing system hardening..."
	default:
		return "Scanning..."
	}
}

func runUpdateCheckBackground(live *domain.ScanProgress, notify func()) {
	live.SetToolStatus("update", domain.ToolRunning, "Checking for updates...")

	version, err := checkLatestVersion()
	if err != nil {
		live.SetToolStatus("update", domain.ToolDone, "Check failed")
		return
	}

	if version == "" || version == strings.TrimPrefix(tui.Version, "v") {
		live.SetToolStatus("update", domain.ToolDone, "Up to date")
	} else {
		live.SetUpdateAvailable(version)
		live.SetToolStatus("update", domain.ToolDone, fmt.Sprintf("v%s available (run 'hostveil update')", version))
	}

	if live.AllToolsDone() {
		live.Finalize()
	}
}

func checkLatestVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/seolcu/hostveil/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
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

	version, err := checkLatestVersion()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	fmt.Printf(" %s\n", version)

	if version == strings.TrimPrefix(tui.Version, "v") {
		fmt.Println("  Already up to date.")
		return nil
	}

	arch := runtime.GOARCH
	if arch == "x86_64" {
		arch = "amd64"
	}
	url := fmt.Sprintf("https://github.com/seolcu/hostveil/releases/download/v%s/hostveil-%s-%s.tar.gz",
		version, runtime.GOOS, arch)

	fmt.Printf("  Downloading hostveil %s...\n", version)
	resp, err := http.Get(url)
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
	fmt.Println("  Updated to v" + version)
	return nil
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
