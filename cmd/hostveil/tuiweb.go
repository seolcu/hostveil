package main

import (
	"flag"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/tui"
	"github.com/seolcu/hostveil/internal/web"
)

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
	reg := newFixRegistry()
	live := domain.NewScanProgress(skipUpdate)
	live.Hostname, _ = os.Hostname()
	live.LocalIP = localIP()

	m := tui.NewApp(live, reg)
	p := tea.NewProgram(m)
	m.SetProgram(func(msg tea.Msg) { p.Send(msg) })

	if !skipUpdate {
		go runUpdateCheckBackground(live)
	}
	if !*noScan {
		launchScanners(live, reg)
	} else {
		skipScanners(live)
	}

	webErr := make(chan error, 1)
	go func() {
		webErr <- web.Serve(web.Options{Addr: *addr, Live: live, Fixes: reg, CertFile: *certFile, KeyFile: *keyFile})
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
