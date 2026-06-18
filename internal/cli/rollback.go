package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/store"
)

var rollbackFlagYes bool

func newRollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback <fix-record-id>",
		Short: "Roll back a previously applied fix",
		Args:  cobra.ExactArgs(1),
		RunE:  runRollback,
	}
	cmd.Flags().BoolVar(&rollbackFlagYes, "yes", false, "skip the interactive confirmation")
	return cmd
}

func runRollback(cmd *cobra.Command, args []string) error {
	paths, err := store.Resolve()
	if err != nil {
		return err
	}
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	s, err := store.Open(paths.StateDB)
	if err != nil {
		return fmt.Errorf("open state.db: %w", err)
	}
	defer s.Close()

	fr, err := s.GetFixRecord(cmd.Context(), args[0])
	if err != nil {
		return fmt.Errorf("load fix record: %w", err)
	}
	if fr.RolledBackAt != nil {
		return fmt.Errorf("fix record has already been rolled back")
	}
	fmt.Fprintf(os.Stderr, "Rolling back %s (affects %s)\n", fr.ID, fr.AffectedPath)
	if !rollbackFlagYes {
		fmt.Fprint(os.Stderr, "Proceed? [y/N] ")
		var ans string
		_, _ = fmt.Scanln(&ans)
		if ans != "y" && ans != "Y" {
			fmt.Fprintln(os.Stderr, "aborted")
			return nil
		}
	}
	res, err := fix.Rollback(s, args[0], time.Now().UTC())
	if err != nil {
		return fmt.Errorf("rollback: %w", err)
	}
	fmt.Fprintf(os.Stderr, "rolled back; follow-up record %s\n", res.FollowUp.ID)
	return nil
}
