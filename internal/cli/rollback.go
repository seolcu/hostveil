package cli

import "github.com/spf13/cobra"

func newRollbackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rollback <fix-record-id>",
		Short: "Roll back a previously applied fix",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("rollback: not yet implemented (Phase 4 deliverable)")
			return nil
		},
	}
}
