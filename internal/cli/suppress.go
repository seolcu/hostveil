package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/store"
)

var (
	suppressFlagList   bool
	suppressFlagReason string
)

func newSuppressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suppress <rule-id>",
		Short: "Suppress a rule's findings on future scans",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runSuppress,
	}
	cmd.Flags().BoolVar(&suppressFlagList, "list", false, "list current suppressions")
	cmd.Flags().StringVar(&suppressFlagReason, "reason", "", "free-text reason for the suppression")
	return cmd
}

// runSuppress adds a suppression rule (or lists existing ones).
// A suppression is a (host_id, rule_id) pair that tells the
// orchestrator to label any matching finding as
// state=suppressed on the next scan.
func runSuppress(cmd *cobra.Command, args []string) error {
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

	// Resolve the host. The suppression is per-host, so we need a
	// host_id; we re-use the orchestrator's host-fingerprint
	// helper.
	host, err := resolveHostForSuppress(s)
	if err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}

	if suppressFlagList || len(args) == 0 {
		return listSuppressions(s, host.ID)
	}
	if err := s.AddSuppression(cmd.Context(), host.ID, args[0], suppressFlagReason); err != nil {
		if err == store.ErrSuppressed {
			fmt.Fprintf(os.Stderr, "rule %q is already suppressed for this host\n", args[0])
			return nil
		}
		return err
	}
	fmt.Fprintf(os.Stderr, "suppressed: %s (host %s)\n", args[0], host.ID)
	return nil
}

// listSuppressions prints the suppression list to stderr in a
// stable order.
func listSuppressions(s *store.Store, hostID string) error {
	rows, err := s.ListSuppressions(nil, hostID)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintf(os.Stderr, "no suppressions for host %s\n", hostID)
		return nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].RuleID != rows[j].RuleID {
			return rows[i].RuleID < rows[j].RuleID
		}
		return rows[i].CreatedAt < rows[j].CreatedAt
	})
	for _, r := range rows {
		reason := r.Reason
		if reason == "" {
			reason = "(no reason given)"
		}
		fmt.Fprintf(os.Stderr, "  %s  %s  %s\n", r.RuleID, r.CreatedAt, reason)
	}
	return nil
}

// resolveHostForSuppress re-uses the orchestrator's host-
// fingerprint logic so suppressions are scoped to the same host
// the scan is run against.
func resolveHostForSuppress(s *store.Store) (model.Host, error) {
	// The simplest path: pick the most recent host row from
	// the store. The orchestrator's hostID helper reads
	// /etc/hostname + /etc/machine-id; that path is duplicated
	// here to avoid a dependency cycle.
	row := s.DB().QueryRow(`
SELECT id, hostname, os_family, COALESCE(os_version, ''),
       kernel, arch, first_seen_at, last_seen_at
FROM hosts
ORDER BY last_seen_at DESC
LIMIT 1`)
	var h model.Host
	var fs, ls string
	if err := row.Scan(&h.ID, &h.Hostname, &h.OSFamily, &h.OSVersion, &h.Kernel, &h.Arch, &fs, &ls); err != nil {
		return model.Host{}, fmt.Errorf("no host row found; run `hostveil scan` first to register this host")
	}
	return h, nil
}
