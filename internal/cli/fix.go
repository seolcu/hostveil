package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/store"
)

var (
	fixFlagYes       bool
	fixFlagNoRestart bool
	fixFlagNoBackup  bool
	fixFlagForce     bool
)

func newFixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fix <finding-id-or-fingerprint>",
		Short: "Apply a built-in fix for a single finding",
		Args:  cobra.ExactArgs(1),
		RunE:  runFix,
	}
	cmd.Flags().BoolVar(&fixFlagYes, "yes", false, "skip the interactive confirmation; the preview is still printed")
	cmd.Flags().BoolVar(&fixFlagNoRestart, "no-restart", false, "if the fix requires a service restart, do not restart it")
	cmd.Flags().BoolVar(&fixFlagNoBackup, "no-backup", false, "skip the backup step (DANGEROUS)")
	cmd.Flags().BoolVar(&fixFlagForce, "force", false, "acknowledge risky behavior (conflict override)")
	return cmd
}

func runFix(cmd *cobra.Command, args []string) error {
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

	f, err := findFinding(s, args[0])
	if err != nil {
		return err
	}
	preview := fix.RenderPreview(f)
	fmt.Fprintln(os.Stderr, preview.String())

	if !fixFlagYes {
		fmt.Fprint(os.Stderr, "Apply this fix? [y/N] ")
		var ans string
		_, _ = fmt.Scanln(&ans)
		if ans != "y" && ans != "Y" {
			fmt.Fprintln(os.Stderr, "aborted")
			return nil
		}
	}

	if fixFlagNoBackup {
		fmt.Fprintln(os.Stderr, "hostveil: --no-backup is not implemented in v3.0.0; ignored")
	}

	run, err := s.LatestScanRunForHost(cmd.Context(), f.Category)
	_ = run
	_ = err

	// In v3.0.0-alpha the fix record's scan_run_id is the most
	// recent scan that produced this finding; fall back to "r-unknown"
	// if no scan is in the DB yet.
	scanRunID := "r-unknown"
	if sr, err := s.LatestScanRunForFinding(cmd.Context(), f); err == nil {
		scanRunID = sr.ID
	}

	res, err := fix.Apply(s, scanRunID, f.ID, f, fixFlagForce, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	if res.FixRecord.BackupPath != "" {
		fmt.Fprintf(os.Stderr, "backup: %s\n", res.FixRecord.BackupPath)
	}
	fmt.Fprintf(os.Stderr, "fix applied: %s\n", res.FixRecord.ID)
	return nil
}

// findFinding looks up a finding by id, falling back to a
// fingerprint search. v3.0.0-alpha searches the most recent
// scan run; the post-v3.0 catalog will accept cross-run queries.
func findFinding(s *store.Store, idOrFP string) (model.Finding, error) {
	fs, err := s.LatestFindings()
	if err != nil {
		return model.Finding{}, fmt.Errorf("load findings: %w", err)
	}
	for _, f := range fs {
		if f.ID == idOrFP || f.Fingerprint == idOrFP {
			return f, nil
		}
	}
	return model.Finding{}, fmt.Errorf("finding %q not found in the most recent scan", idOrFP)
}
