package cli

import "github.com/spf13/cobra"

func newSuppressCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "suppress <rule-id>",
		Short: "Suppress a rule's findings on future scans",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("suppress: not yet implemented (Phase 6 deliverable)")
			return nil
		},
	}
}
