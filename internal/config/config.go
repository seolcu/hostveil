package config

import (
	"flag"
	"fmt"
	"os"
)

type Config struct {
	UserMode    bool   // limit to user privileges
	ShowHelp    bool
	ShowVersion bool
}

func Parse() (*Config, error) {
	cfg := &Config{}

	flag.BoolVar(&cfg.UserMode, "user-mode", false, "run without root/sudo")
	flag.BoolVar(&cfg.ShowHelp, "help", false, "show help")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `hostveil - Linux Self-Hosting Security Scanner

Usage:
  hostveil                    TUI: auto-discover compose files + adapters
  hostveil --user-mode        Run without root/sudo (limited checks)
  hostveil --version

Options:
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
