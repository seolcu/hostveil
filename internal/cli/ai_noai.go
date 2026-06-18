//go:build noai

package cli

import "github.com/spf13/cobra"

// addAIIfPresent is a no-op in the noai build per SC-010.
func addAIIfPresent(_ *cobra.Command) {}
