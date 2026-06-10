package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/seolcu/hostveil/internal/history"
)

func runHistory(args []string) error {
	if len(args) > 0 && args[0] == "--scans" {
		return runScanHistory()
	}
	if len(args) > 0 && args[0] == "show" && len(args) > 1 {
		return showCheckpoint(args[1])
	}

	cps, err := history.ListCheckpoints()
	if err != nil {
		return fmt.Errorf("list checkpoints: %w", err)
	}
	if len(cps) == 0 {
		fmt.Println("  No checkpoints found.")
		return nil
	}

	fmt.Printf("  %d checkpoint(s):\n\n", len(cps))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  ID\tWhen\tFinding\tAction")
	for _, cp := range cps {
		ts := cp.Timestamp.Format("2006-01-02 15:04")
		finding := cp.FindingID
		if len(finding) > 24 {
			finding = finding[:21] + "..."
		}
		action := cp.Action
		if len(action) > 32 {
			action = action[:29] + "..."
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", cp.ID, ts, finding, action)
	}
	w.Flush()
	fmt.Println()
	fmt.Println("  Use 'hostveil history show <id>' to view details.")
	fmt.Println("  Use 'hostveil rollback <id>' to restore.")
	return nil
}

func showCheckpoint(id string) error {
	cp, err := history.GetCheckpoint(id)
	if err != nil {
		return err
	}

	fmt.Printf("  Checkpoint: %s\n", cp.ID)
	fmt.Printf("  Time:       %s\n", cp.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Finding:    %s\n", cp.FindingID)
	if cp.Service != "" {
		fmt.Printf("  Service:    %s\n", cp.Service)
	}
	fmt.Printf("  Action:     %s\n", cp.Action)
	fmt.Println()

	if len(cp.Backups) > 0 {
		fmt.Printf("  Backed up %d file(s):\n", len(cp.Backups))
		for _, b := range cp.Backups {
			fmt.Printf("    %s\n", b.OriginalPath)
		}
		fmt.Println()
	}

	if cp.Diff != "" {
		fmt.Println("  Diff:")
		for _, line := range strings.Split(cp.Diff, "\n") {
			fmt.Printf("    %s\n", line)
		}
		fmt.Println()
	}

	if cp.Restart != nil {
		fmt.Printf("  After rollback: %s\n", cp.Restart.Description)
	}

	return nil
}

func runRollback(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "  Usage: hostveil rollback <checkpoint-id>")
		return fmt.Errorf("missing checkpoint ID")
	}

	id := args[0]
	cp, err := history.GetCheckpoint(id)
	if err != nil {
		return err
	}

	fmt.Printf("  Rolling back checkpoint %s...\n", cp.ID)
	fmt.Printf("  Finding: %s\n", cp.FindingID)
	fmt.Printf("  Action:  %s\n", cp.Action)
	fmt.Println()

	if len(cp.Backups) == 0 {
		fmt.Println("  No files to restore.")
		return nil
	}

	// Show what will be restored
	fmt.Printf("  Will restore %d file(s):\n", len(cp.Backups))
	for _, b := range cp.Backups {
		fmt.Printf("    %s\n", b.OriginalPath)
	}
	fmt.Println()

	// Confirm
	fmt.Print("  Proceed? [y/N] ")
	var answer string
	fmt.Scanln(&answer)
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		fmt.Println("  Aborted.")
		return nil
	}

	// Perform rollback
	result, err := history.Rollback(*cp)
	if err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %s\n", result.Message)

	for _, f := range result.RestoredFiles {
		fmt.Printf("    Restored: %s\n", f)
	}

	// Handle service restart
	if result.Restart != nil {
		fmt.Println()
		fmt.Printf("  %s may need to be restarted.\n", result.Restart.ServiceName)
		fmt.Printf("  Command: %s\n", result.Restart.Command)
		fmt.Print("  Restart now? [y/N] ")
		var restartAnswer string
		fmt.Scanln(&restartAnswer)
		if strings.ToLower(strings.TrimSpace(restartAnswer)) == "y" {
			msg, err := history.RestartService(*result.Restart)
			if err != nil {
				fmt.Printf("  Warning: %s\n", msg)
			} else {
				fmt.Printf("  %s\n", msg)
			}
		} else {
			fmt.Printf("  Skipped. Run manually: %s\n", result.Restart.Command)
		}
	}

	fmt.Println()
	fmt.Println("  Rollback complete.")
	return nil
}

func runScanHistory() error {
	scans, err := history.ListScans()
	if err != nil {
		return fmt.Errorf("list scans: %w", err)
	}
	if len(scans) == 0 {
		fmt.Println("  No scan history found.")
		return nil
	}

	fmt.Printf("  %d scan(s):\n\n", len(scans))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  ID\tTime\tScore\tFindings")
	for _, s := range scans {
		ts := s.Timestamp.Format("2006-01-02 15:04")
		fmt.Fprintf(w, "  %s\t%s\t%d/100\t%d\n", s.ID, ts, s.Snapshot.Score, len(s.Snapshot.Findings))
	}
	w.Flush()

	// Show diff between last two scans if available
	if len(scans) >= 2 {
		fmt.Println()
		diff := diffScans(scans[1], scans[0])
		if diff != "" {
			fmt.Println("  Changes since last scan:")
			fmt.Println(diff)
		}
	}

	return nil
}

func diffScans(old, new history.ScanRecord) string {
	oldIDs := make(map[string]bool)
	for _, f := range old.Snapshot.Findings {
		oldIDs[f.ID] = true
	}
	newIDs := make(map[string]bool)
	for _, f := range new.Snapshot.Findings {
		newIDs[f.ID] = true
	}

	var lines []string
	for _, f := range new.Snapshot.Findings {
		if !oldIDs[f.ID] {
			lines = append(lines, fmt.Sprintf("    + New: %s (%s)", f.ID, f.Title))
		}
	}
	for _, f := range old.Snapshot.Findings {
		if !newIDs[f.ID] {
			lines = append(lines, fmt.Sprintf("    - Gone: %s (%s)", f.ID, f.Title))
		}
	}
	scoreDiff := int(new.Snapshot.Score) - int(old.Snapshot.Score)
	sign := "+"
	if scoreDiff < 0 {
		sign = ""
	}
	if scoreDiff != 0 {
		lines = append(lines, fmt.Sprintf("    Score: %d → %d (%s%d)", old.Snapshot.Score, new.Snapshot.Score, sign, scoreDiff))
	}

	return strings.Join(lines, "\n")
}
