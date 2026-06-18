package cli

import (
	"github.com/spf13/cobra"

	"github.com/seolcu/hostveil/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(version.String())
		},
	}
}
