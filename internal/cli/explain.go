package cli

import "github.com/spf13/cobra"

func newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <finding-id-or-rule-id>",
		Short: "Explain a finding or rule in plain language",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("explain: not yet implemented (Phase 6 deliverable)")
			return nil
		},
	}
}
