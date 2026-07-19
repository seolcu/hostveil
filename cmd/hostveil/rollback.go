package main

import (
	"fmt"
	"os"
)

func cmdRollback(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: hostveil rollback <checkpoint-id>")
		return 2
	}
	out, err := buildEngine().Rollback(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil: rollback failed:", err)
		return 1
	}
	fmt.Printf("✓ Rolled back checkpoint %s.\n", out.CheckpointID)
	for _, p := range out.RestoredFiles {
		fmt.Printf("  restored %s\n", p)
	}
	if out.RestartService != "" {
		fmt.Printf("  You may need to restart the '%s' service.\n", out.RestartService)
	}
	return 0
}

func cmdHistory(args []string) int {
	_ = args
	cps, err := buildEngine().ListCheckpoints()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	if len(cps) == 0 {
		fmt.Println("No fixes have been applied yet.")
		return 0
	}
	fmt.Println("Applied fixes (newest first):")
	for _, cp := range cps {
		reversible := "not reversible"
		if cp.Reversible {
			reversible = "rollback: hostveil rollback " + cp.ID
		}
		fmt.Printf("  %s  %s  (%s)  [%s]\n",
			cp.CreatedAt.Format("2006-01-02 15:04:05"), cp.FindingID, cp.Label, reversible)
	}
	return 0
}
