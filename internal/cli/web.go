package cli

import "github.com/spf13/cobra"

func newWebCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "web",
		Short: "Start the localhost web dashboard",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("web: not yet implemented (Phase 7 deliverable)")
			return nil
		},
	}
}
