package cli

import "github.com/spf13/cobra"

func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive terminal UI (requires a TTY)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("tui: not yet implemented (Phase 5 deliverable)")
			return nil
		},
	}
}
