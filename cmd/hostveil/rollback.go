package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/core"
)

func cmdRollback(args []string) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	force := fs.Bool("force", false, "restore even if the file changed after the fix was applied")

	// Accept the ID before the flags ("rollback <id> --force"), matching how
	// `fix` handles the same shape.
	var id string
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		id, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		fmt.Fprintln(os.Stderr, "usage: hostveil rollback <checkpoint-id> [--force]")
		return 2
	}

	engine := buildEngine()
	out, err := engine.Rollback(id)

	// Declining is not failing. The file changed after hostveil wrote it, so
	// restoring the backup would discard whatever was done in between — and
	// rollback keeps no checkpoint of its own, so there would be no way back.
	// Say exactly that, and let the user decide.
	if core.IsExternalEdit(err) {
		if !*force {
			fmt.Fprintf(os.Stderr, "hostveil: %v\n", err)
			fmt.Fprintln(os.Stderr, "  Rolling back would overwrite it with the pre-fix backup and discard those edits.")
			fmt.Fprintln(os.Stderr, "  Rollback keeps no backup of its own, so this cannot be undone.")
			fmt.Fprintf(os.Stderr, "  Save a copy first, then: hostveil rollback %s --force\n", id)
			return 1
		}
		out, err = engine.RollbackForce(id)
	}
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
