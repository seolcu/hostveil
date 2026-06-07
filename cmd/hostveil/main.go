package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/scan"
	"github.com/seolcu/hostveil/internal/tui"
	"github.com/seolcu/hostveil/internal/web"
)

var httpClient = &http.Client{Timeout: domain.HTTPClientTimeout}

var checkLatestURL = "https://api.github.com/repos/seolcu/hostveil/releases/latest"
var installerURL = "https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh"

var fixRegistry *fix.Registry

func init() {
	fixRegistry = fix.New()
	fix.RegisterAll(fixRegistry)
}

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
			if hasFlag(os.Args, "--fixture") {
				return runServe(os.Args[2:])
			}
			ensureSudo()
			return runServe(os.Args[2:])
		case "tui-web":
			ensureSudo()
			return runTUIWeb(os.Args[2:])
		case "--help", "-h":
			printHelp()
			return nil
		case "--version", "-v":
			fmt.Println("hostveil", tui.Version)
			return nil
		}
	}

	ensureSudo()
	noUpdate := hasFlag(os.Args, "--no-update")
	noScan := hasFlag(os.Args, "--no-scan")

	live := domain.NewScanProgress(noUpdate)
	live.Hostname, _ = os.Hostname()
	live.LocalIP = localIP()

	m := tui.NewApp(live, fixRegistry)
	p := tea.NewProgram(m)
	m.SetProgram(func(msg tea.Msg) { p.Send(msg) })

	if !noUpdate {
		go runUpdateCheckBackground(live)
	}
	if !noScan {
		go scan.RunSingleTool(live, fixRegistry, "trivy")
		go scan.RunSingleTool(live, fixRegistry, "lynis")
	} else {
		live.SetToolStatus("trivy", domain.ToolSkipped, "Skipped (--no-scan)")
		live.SetToolStatus("lynis", domain.ToolSkipped, "Skipped (--no-scan)")
		live.Finalize()
	}

	_, err := p.Run()
	return err
}

func runTUIWeb(args []string) error {
	fs := flag.NewFlagSet("tui-web", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "127.0.0.1:8787", "address to serve the web UI on")
	certFile := fs.String("cert-file", "", "TLS certificate file (enables HTTPS)")
	keyFile := fs.String("key-file", "", "TLS private key file")
	noUpdate := fs.Bool("no-update", false, "skip update check on startup")
	noScan := fs.Bool("no-scan", false, "skip scanning, open immediately")
	if err := fs.Parse(args); err != nil {
		return err
	}

	skipUpdate := *noUpdate || hasFlag(os.Args, "--no-update")
	live := domain.NewScanProgress(skipUpdate)
	live.Hostname, _ = os.Hostname()
	live.LocalIP = localIP()

	m := tui.NewApp(live, fixRegistry)
	p := tea.NewProgram(m)
	m.SetProgram(func(msg tea.Msg) { p.Send(msg) })

	if !skipUpdate {
		go runUpdateCheckBackground(live)
	}
	if !*noScan {
		go scan.RunSingleTool(live, fixRegistry, "trivy")
		go scan.RunSingleTool(live, fixRegistry, "lynis")
	} else {
		live.SetToolStatus("trivy", domain.ToolSkipped, "Skipped (--no-scan)")
		live.SetToolStatus("lynis", domain.ToolSkipped, "Skipped (--no-scan)")
		live.Finalize()
	}

	webErr := make(chan error, 1)
	go func() {
		webErr <- web.Serve(web.Options{Addr: *addr, Live: live, Fixes: fixRegistry, CertFile: *certFile, KeyFile: *keyFile})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-webErr:
			return err
		default:
		}
		time.Sleep(500 * time.Millisecond)
	}

	_, err := p.Run()
	if err != nil {
		return err
	}
	select {
	case err := <-webErr:
		return err
	default:
		return nil
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "127.0.0.1:8787", "address to serve the web UI on")
	certFile := fs.String("cert-file", "", "TLS certificate file (enables HTTPS)")
	keyFile := fs.String("key-file", "", "TLS private key file")
	noUpdate := fs.Bool("no-update", false, "skip update check on startup")
	noScan := fs.Bool("no-scan", false, "skip scanning, serve immediately")
	fixture := fs.String("fixture", "", "path to fixture JSON (for E2E testing)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fixture != "" {
		return serveFixture(*fixture, *addr, *certFile, *keyFile)
	}

	skipUpdate := *noUpdate || hasFlag(os.Args, "--no-update")
	live := domain.NewScanProgress(skipUpdate)
	live.Hostname, _ = os.Hostname()
	live.LocalIP = localIP()

	if !skipUpdate {
		go runUpdateCheckBackground(live)
	}
	if !*noScan {
		go scan.RunSingleTool(live, fixRegistry, "trivy")
		go scan.RunSingleTool(live, fixRegistry, "lynis")
	} else {
		live.SetToolStatus("trivy", domain.ToolSkipped, "Skipped (--no-scan)")
		live.SetToolStatus("lynis", domain.ToolSkipped, "Skipped (--no-scan)")
		live.Finalize()
	}

	if *certFile != "" && *keyFile != "" {
		fmt.Printf("  Starting Web UI at https://%s\n", *addr)
	} else {
		fmt.Printf("  Starting Web UI at http://%s\n", *addr)
	}
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		os.Exit(0)
	}()

	return web.Serve(web.Options{Addr: *addr, Live: live, Fixes: fixRegistry, CertFile: *certFile, KeyFile: *keyFile})
}

type fixtureData struct {
	Hostname string           `json:"hostname"`
	LocalIP  string           `json:"local_ip"`
	Findings []domain.Finding `json:"findings"`
}

func serveFixture(fixturePath, addr, certFile, keyFile string) error {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}

	var fixture fixtureData
	if err := json.Unmarshal(data, &fixture); err != nil {
		return fmt.Errorf("parse fixture: %w", err)
	}

	live := domain.NewScanProgress(true)

	if fixture.Hostname != "" {
		live.Hostname = fixture.Hostname
	} else {
		live.Hostname, _ = os.Hostname()
	}
	if fixture.LocalIP != "" {
		live.LocalIP = fixture.LocalIP
	} else {
		live.LocalIP = localIP()
	}

	registerFixtureFixes(fixRegistry, fixture.Findings)

	loadFixtureIntoLive := func(l *domain.ScanProgress) {
		findings := make([]domain.Finding, len(fixture.Findings))
		copy(findings, fixture.Findings)
		if len(findings) > 0 {
			fixRegistry.Classify(findings)
			l.AddFindings(findings)
		}
		l.SetToolStatus("trivy", domain.ToolDone, fmt.Sprintf("Found %d issues (fixture)", len(findings)))
		l.SetToolStatus("lynis", domain.ToolDone, "Fixture loaded")
		l.Finalize()
	}

	loadFixtureIntoLive(live)

	if fixture.Hostname != "" {
		live.Hostname = fixture.Hostname
	}
	if fixture.LocalIP != "" {
		live.LocalIP = fixture.LocalIP
	}

	rescanFn := func() {
		loadFixtureIntoLive(live)
	}

	fmt.Printf("  Starting Web UI (fixture mode) at http://%s\n", addr)
	fmt.Println("  Press Ctrl+C to stop.")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		os.Exit(0)
	}()

	return web.Serve(web.Options{Addr: addr, Live: live, Fixes: fixRegistry, CertFile: certFile, KeyFile: keyFile, RescanFn: rescanFn})
}

func registerFixtureFixes(r *fix.Registry, findings []domain.Finding) {
	for _, finding := range findings {
		f := finding
		if f.Remediation == domain.RemediationUnavailable {
			continue
		}
		actions := []fix.Action{
			{Type: fix.ActionExec, Label: "Apply mock fix", Apply: func(ctx fix.Context) error { return nil }},
		}
		if f.Remediation == domain.RemediationReview {
			actions = append(actions, fix.Action{
				Type: fix.ActionExec, Label: "Alternative mock fix",
				Apply: func(ctx fix.Context) error { return nil },
			})
		}
		r.Register(&fix.Fix{
			FindingID: f.ID,
			Label:     "Mock fix for " + f.ID,
			Actions:   actions,
		})
	}
}

func runUpdateCheckBackground(live *domain.ScanProgress) {
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
	resp, err := httpClient.Get(checkLatestURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == 429 {
			return "", fmt.Errorf("GitHub API rate limited (status %d). Use --no-update or set --version", resp.StatusCode)
		}
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

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

	tmpFile := "/tmp/hostveil-install.sh"
	resp, err := httpClient.Get(installerURL)
	if err != nil {
		return fmt.Errorf("failed to download installer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("installer download failed: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmpFile)
		return err
	}

	data, _ := os.ReadFile(tmpFile)
	if len(data) == 0 || !strings.HasPrefix(string(data), "#!/") {
		os.Remove(tmpFile)
		return fmt.Errorf("downloaded installer looks invalid")
	}

	os.Chmod(tmpFile, 0755)

	fmt.Println("  Downloaded installer script. Running...")
	fmt.Println()

	cmd := exec.Command(tmpFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	os.Remove(tmpFile)
	return err
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
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

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

	if err := exec.Command("tar", "xzf", tmpFile, "-C", "/tmp").Run(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("archive extraction failed: %w", err)
	}
	if err := exec.Command("install", "-m", "755", "/tmp/hostveil", "/usr/bin/hostveil").Run(); err != nil {
		return fmt.Errorf("install failed: %w", err)
	}
	os.Remove(tmpFile)
	fmt.Println("  Updated to v" + version)
	return nil
}

func printHelp() {
	fmt.Println(helpText())
}

func helpText() string {
	return `hostveil — Linux self-hosting security scanner

Usage:
  hostveil                    Scan and open TUI
  hostveil --no-scan          Open TUI without scanning
  hostveil serve              Scan and serve Web UI on 127.0.0.1:8787
  hostveil serve --no-scan    Serve Web UI immediately (no scan)
  hostveil web                Alias for serve
  hostveil tui-web            Open TUI and serve Web UI at the same time
  hostveil serve --addr ADDR  Serve Web UI on a custom address
  hostveil tui-web --addr ADDR  TUI plus Web UI on a custom address
  hostveil serve --cert-file CERT --key-file KEY  Serve with HTTPS
  hostveil setup              Install dependencies (trivy, lynis)
  hostveil update             Update to the latest version
  hostveil --no-update        Skip update check on startup
  hostveil serve --fixture F  Serve fixture data (E2E testing)
  hostveil --version          Show version
  hostveil --help             Show this help`
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func localIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

func ensureSudo() {
	if os.Geteuid() == 0 {
		return
	}
	cmd := exec.Command("sudo", os.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil requires root access.")
		os.Exit(1)
	}
	os.Exit(0)
}
