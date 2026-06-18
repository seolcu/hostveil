// Package cli owns the cobra command tree, persistent flag set, and
// exit-code contract (0 = no high/critical, 1 = at least one
// high/critical, 2 = scan errored). The subcommands themselves
// live in their respective files (scan.go, fix.go, etc.).
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Persistent flags wired to every subcommand. Defined in init() so
// tests can construct the root command without re-parsing os.Args.
var (
	flagConfig   string
	flagLogLevel string
	flagLogFile  string
	flagNoColor  bool
	flagColor    string
)

// NewRoot returns the root cobra command with all persistent flags
// and subcommands attached. main.go calls this once and Execute's it.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "hostveil",
		Short:         "Self-host security scanner & fixer for non-experts",
		Long:          "Hostveil scans a Linux host for SSH, Docker, image-CVE, reverse-proxy, SSL/TLS, and system-hardening issues, presents the findings in plain language, and applies reversible fixes.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&flagConfig, "config", defaultConfigPath(), "path to the user config file")
	root.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "log level: debug, info, warn, error")
	root.PersistentFlags().StringVar(&flagLogFile, "log-file", "", "if set, structured logs are also written to this file (JSON)")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable ANSI color in the text report")
	root.PersistentFlags().StringVar(&flagColor, "color", "auto", "color mode: auto, always, never")

	// Subcommands.
	root.AddCommand(newScanCmd())
	root.AddCommand(newFixCmd())
	root.AddCommand(newRollbackCmd())
	root.AddCommand(newExplainCmd())
	root.AddCommand(newSuppressCmd())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newTUICmd())
	root.AddCommand(newWebCmd())
	root.AddCommand(newAICmd())

	return root
}

func defaultConfigPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return fmt.Sprintf("%s/.config/hostveil/config.toml", home)
	}
	return "hostveil.toml"
}

// Execute runs the root command and returns the process exit code.
func Execute() int {
	if err := NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		// Expose the sentinel for the main entry point so it can
		// translate the "high or critical finding" case to exit 1.
		if _, ok := err.(HitError); ok {
			return ExitHit
		}
		return ExitError
	}
	return ExitOK
}
