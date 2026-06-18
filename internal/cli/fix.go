package cli

import "github.com/spf13/cobra"

func newFixCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fix <finding-id-or-fingerprint>",
		Short: "Apply a built-in fix for a single finding",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("fix: not yet implemented (Phase 4 deliverable)")
			return nil
		},
	}
}
