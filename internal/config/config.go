package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	ComposePath string
	HostRoot    string
	OutputMode  string // tui, json, sarif, markdown, html
	FindingsOnly bool
	Serve       bool
	Port        int
	Host        string
	FixMode     string // "", "auto", "full"
	FixPath     string
	PreviewOnly bool
	AssumeYes   bool
	UserMode    bool
	ShowHelp    bool
	ShowVersion bool
}

func Parse() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.ComposePath, "compose", "", "override live discovery with a specific Compose file or directory")
	flag.StringVar(&cfg.HostRoot, "host-root", "", "override the default live host root (/) with a Linux root or snapshot")
	flag.StringVar(&cfg.OutputMode, "output", "tui", "output mode: tui, json, sarif, markdown, html")
	flag.BoolVar(&cfg.FindingsOnly, "findings-only", false, "emit only the findings array when used with --output json")
	flag.BoolVar(&cfg.Serve, "serve", false, "start web server")
	flag.IntVar(&cfg.Port, "port", 8080, "web server port")
	flag.StringVar(&cfg.Host, "host", "127.0.0.1", "web server bind address")
	flag.StringVar(&cfg.FixMode, "fix", "", "fix mode: auto or full compose file path")
	flag.StringVar(&cfg.FixPath, "fix-path", "", "path for fix target")
	flag.BoolVar(&cfg.PreviewOnly, "preview-changes", false, "show the planned diff without writing any files")
	flag.BoolVar(&cfg.AssumeYes, "yes", false, "apply the reviewed changes without confirmation")
	flag.BoolVar(&cfg.UserMode, "user-mode", false, "run without root/sudo privileges")
	flag.BoolVar(&cfg.ShowHelp, "help", false, "show help")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `hostveil - Linux Self-Hosting Security Scanner

Usage:
  hostveil
  hostveil --output json
  hostveil --compose PATH
  hostveil --serve [--port PORT]
  hostveil --fix PATH [--preview-changes]

Options:
  --compose PATH      override live discovery with a specific Compose file or directory
  --host-root PATH    override the default live host root
  --output MODE       output mode: tui, json, sarif, markdown, html
  --findings-only     emit only findings array with --output json
  --fix PATH          preview or apply fixes for a compose file
  --preview-changes   show the planned diff without writing
  --yes               apply changes without confirmation
  --user-mode         run without sudo
  --serve             start web server
  --port N            web server port (default: 8080)
  --host ADDR         web server bind address (default: 127.0.0.1)
  --version           show version
  --help              show this help
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

	// --fix implies fix mode
	if cfg.FixMode != "" {
		cfg.FixPath = cfg.FixMode
		cfg.FixMode = "full"
	}

	// Resolve compose path
	if cfg.ComposePath != "" {
		abs, err := filepath.Abs(cfg.ComposePath)
		if err == nil {
			cfg.ComposePath = abs
		}
	}

	return cfg, nil
}
