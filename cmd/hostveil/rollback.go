package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/history"
)

func cmdRollback(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	force := fs.Bool("force", false, "restore even if the file changed after the fix was applied")

	// Accept the ID before the flags ("rollback <id> --force"), matching how
	// `fix` handles the same shape.
	var id string
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		id, args = args[0], args[1:]
	}
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		fmt.Fprintln(os.Stderr, "usage: hostveil rollback <checkpoint-id> [--force]")
		return 2
	}

	engine := newEngine()
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

// cmdHistory takes no flags, which is not the same as ignoring them. It
// used to discard args entirely, so `hostveil history --json` — a flag a
// user has every reason to expect, and which the CLI reference says does
// not exist — printed the human table and exited 0. Every other subcommand
// exits 2 on an unknown flag. Parsing an empty flag set is what makes the
// documented "no flags" true rather than merely written down.
func cmdHistory(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}
	cps, err := newEngine().ListCheckpoints()
	// An unreadable checkpoint is a warning over a usable list, not a failure:
	// the entries that survived still name fixes the operator can roll back,
	// and staying silent about the rest would hide that part of their recovery
	// history is gone.
	if core.IsIncompleteHistory(err) {
		fmt.Fprintln(os.Stderr, "hostveil: warning:", err)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	if len(cps) == 0 {
		fmt.Println("No fixes have been applied yet.")
		warnAboutStateDirectory()
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

// warnAboutStateDirectory explains an empty history that is not really
// empty.
//
// Checkpoints live in /var/lib/hostveil when root and ~/.local/share/hostveil
// otherwise, so a fix applied as root and a later unprivileged `hostveil
// history` read different directories. The user is then told "No fixes have
// been applied yet" about a host they fixed ten minutes ago, with nothing
// pointing at the reason. Only shown when the history is empty *and* the run
// is unprivileged, so it never nags anyone whose setup is fine.
func warnAboutStateDirectory() {
	if os.Geteuid() == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"\nhostveil: reading %s because this run is not root.\n"+
			"Fixes applied as root are recorded in /var/lib/hostveil instead — re-run with sudo to see those.\n",
		history.DefaultDir())
}
