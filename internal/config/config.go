package config

import (
	"flag"
	"fmt"
	"os"
)

type Config struct {
	Serve       bool   // web server mode
	Port        int    // web server port
	Host        string // web server bind address
	UserMode    bool   // limit to user privileges
	ShowHelp    bool
	ShowVersion bool
}

func Parse() (*Config, error) {
	cfg := &Config{}

	flag.BoolVar(&cfg.Serve, "serve", false, "start web server (ttyd)")
	flag.IntVar(&cfg.Port, "port", 8080, "web server port")
	flag.StringVar(&cfg.Host, "host", "127.0.0.1", "web server bind address")
	flag.BoolVar(&cfg.UserMode, "user-mode", false, "run without root/sudo")
	flag.BoolVar(&cfg.ShowHelp, "help", false, "show help")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `hostveil - Linux Self-Hosting Security Scanner

Usage:
  hostveil                    # TUI: auto-discover compose files + adapters
  hostveil --serve            # Web TUI via ttyd (http://127.0.0.1:8080)
  hostveil --user-mode        # Run without root/sudo (limited checks)
  hostveil --version

Options:
  --serve       start web server (ttyd)
  --port N      web server port (default: 8080)
  --host ADDR   web server bind address (default: 127.0.0.1)
  --user-mode   run without root/sudo (limited checks)
  --version     show version
  --help        show this help
`)
	}

	if len(os.Args) < 2 {
		return cfg, nil
	}

	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		flag.Usage()
		os.Exit(0)
	}

	if os.Args[1] == "--version" || os.Args[1] == "-V" {
		fmt.Println("hostveil v1.0.0")
		os.Exit(0)
	}

	flag.CommandLine.Parse(os.Args[1:])

	return cfg, nil
}
