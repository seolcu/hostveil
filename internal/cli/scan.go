package cli

import "github.com/spf13/cobra"

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Run a full or partial scan and write a report",
		Long:  "Runs a full or partial scan of the host and writes a plain-language report to stdout and to the on-disk report file. Per the spec, this is the canonical entry point.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("scan: not yet implemented (Phase 3 deliverable)")
			return nil
		},
	}
}
