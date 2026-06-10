package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/web"
)

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
	reg := newFixRegistry()
	live := domain.NewScanProgress(skipUpdate)
	live.Hostname, _ = os.Hostname()
	live.LocalIP = localIP()

	if !skipUpdate {
		go runUpdateCheckBackground(live)
	}
	if !*noScan {
		launchScanners(live, reg)
	} else {
		skipScanners(live)
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

	errCh := make(chan error, 1)
	go func() {
		errCh <- web.Serve(web.Options{Addr: *addr, Live: live, Fixes: reg, CertFile: *certFile, KeyFile: *keyFile})
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

type fixtureData struct {
	Hostname string           `json:"hostname"`
	LocalIP  string           `json:"local_ip"`
	Findings []domain.Finding `json:"findings"`
}

func serveFixture(fixturePath, addr, certFile, keyFile string) error {
	data, err := os.ReadFile(fixturePath) //nolint:gosec // CLI-provided path
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}

	var fixture fixtureData
	if err := json.Unmarshal(data, &fixture); err != nil {
		return fmt.Errorf("parse fixture: %w", err)
	}

	reg := newFixRegistry()
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

	registerFixtureFixes(reg, fixture.Findings)

	loadFixtureIntoLive := func(l *domain.ScanProgress) {
		findings := make([]domain.Finding, len(fixture.Findings))
		copy(findings, fixture.Findings)
		if len(findings) > 0 {
			reg.Classify(findings)
			l.AddFindings(findings)
		}
		l.SetToolStatus("trivy", domain.ToolDone, fmt.Sprintf("Found %d issues (fixture)", len(findings)))
		l.SetToolStatus("lynis", domain.ToolDone, "Fixture loaded")
		l.Finalize()
	}

	loadFixtureIntoLive(live)

	rescanFn := func() {
		loadFixtureIntoLive(live)
	}

	scheme := "http"
	if certFile != "" && keyFile != "" {
		scheme = "https"
	}
	fmt.Printf("  Starting Web UI (fixture mode) at %s://%s\n", scheme, addr)
	fmt.Println("  Press Ctrl+C to stop.")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- web.Serve(web.Options{Addr: addr, Live: live, Fixes: reg, CertFile: certFile, KeyFile: keyFile, RescanFn: rescanFn})
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
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
