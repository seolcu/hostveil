package cli

import "github.com/spf13/cobra"

func newAICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai <method>",
		Short: "AI-assisted explanation / risk / recommend (opt-in)",
		Long:  "hostveil ai explain|risk|recommend|configure|list. AI is opt-in per call; defaults to local Ollama. Cloud providers require explicit consent (FR-030).",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "explain <finding-id>",
		Short: "AI-assisted plain-language explanation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("ai explain: not yet implemented (Phase 8 deliverable)")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "risk <finding-id>",
		Short: "AI-assisted risk assessment",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("ai risk: not yet implemented (Phase 8 deliverable)")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "recommend <finding-id>",
		Short: "AI-assisted fix recommendation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("ai recommend: not yet implemented (Phase 8 deliverable)")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "configure",
		Short: "Add or update an AI provider",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("ai configure: not yet implemented (Phase 8 deliverable)")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List configured AI providers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("ai list: not yet implemented (Phase 8 deliverable)")
			return nil
		},
	})
	return cmd
}
