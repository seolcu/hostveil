package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/model"
)

// newEngine is how every command obtains its engine. It is a variable so a
// test can supply one wired to a fake runner and a temp state directory —
// otherwise `fix` and `rollback`, the two commands that mutate the host,
// could only be exercised by scanning the machine running the tests.
var newEngine = func() *core.Engine { return buildEngine() }

// newEngineWithAI is the same seam for the three commands that offer the
// advisory explainer. It exists so `explain` is reachable from a test the
// way `fix` and `rollback` are; without it, explain built its engine
// directly and could only be exercised by scanning the machine running the
// tests.
var newEngineWithAI = func(useAI bool) *core.Engine { return buildEngineWithAI(useAI) }

func cmdFix(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	var (
		service string
		action  int
		yes     bool
		review  bool
		all     bool
	)
	fs.StringVar(&service, "service", "", "disambiguate a finding by service name")
	fs.IntVar(&action, "action", -1, "for Review fixes, the alternative to apply (0-based)")
	fs.BoolVar(&yes, "yes", false, "apply without an interactive confirmation")
	fs.BoolVar(&review, "review", false, "with --all, also apply Review fixes (their first alternative)")
	fs.BoolVar(&all, "all", false, "apply every safe (Auto) fix at once")

	// Allow the finding ID to come before flags ("fix <id> --yes"), which
	// Go's flag package would otherwise stop parsing at.
	var findingID string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		findingID, args = args[0], args[1:]
	}
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}

	if all {
		// --all applies every Auto fix on the host, so there is no one
		// finding to disambiguate and no alternative to pick — Auto fixes
		// have exactly one action by definition. Both flags parsed into
		// this set and were then silently dropped, which is the worst
		// available answer: `fix --all --action 1` looked like it chose
		// something. Say so instead.
		if service != "" || action >= 0 {
			fmt.Fprintln(os.Stderr, "hostveil: --service and --action apply to a single finding and cannot be combined with --all")
			return 2
		}
		if findingID != "" || fs.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "hostveil: --all applies every safe fix; do not also name a finding")
			return 2
		}
		return fixAll(ctx, yes, review)
	}
	if findingID == "" {
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "usage: hostveil fix <finding-id> [--service NAME] [--action N] [--yes]")
			return 2
		}
		findingID = fs.Arg(0)
	}

	engine := newEngine()
	report := engine.Scan(ctx, nil)

	finding, ok := findFinding(report, findingID, service)
	if !ok {
		fmt.Fprintf(os.Stderr, "hostveil: no active finding %q%s\n", findingID, serviceSuffix(service))
		return 1
	}
	if !finding.IsFixable() {
		fmt.Fprintf(os.Stderr, "hostveil: %s is %s — hostveil cannot fix it automatically.\nGuidance: %s\n",
			finding.ID, finding.Remediation.Label(), finding.HowToFix)
		return 1
	}

	preview, err := engine.PreviewFix(finding)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}

	chosen, err := resolveAction(preview, action, yes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}

	printPreview(finding, preview, chosen)

	if !yes && !promptYesNo("Apply this fix?") {
		fmt.Println("Aborted. Nothing changed.")
		return 0
	}

	outcome, err := engine.ApplyFix(ctx, finding, chosen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil: fix failed:", err)
		return 1
	}
	printOutcome(outcome)
	return 0
}

// fixAll previews and applies every safe (Auto) fix in one pass.
// fixAll applies every fix the tool can apply unattended, and with --review
// every fix it can apply at all.
//
// The two lists are printed separately and counted separately, because they
// are different promises. An Auto fix is reversible, cannot cut off access to
// the host, and has one correct answer. A Review fix is one hostveil can
// perform and will not perform for you: it may be an exec action with no
// checkpoint, or it may have more than one defensible remediation, and
// --review is where the operator says they have read that and accept it.
func fixAll(ctx context.Context, yes, review bool) int {
	engine := newEngine()
	report := engine.Scan(ctx, nil)

	var auto, reviewed []model.Finding
	for _, f := range report.Findings {
		if f.Fixed {
			continue
		}
		switch f.Remediation {
		case model.RemediationAuto:
			auto = append(auto, f)
		case model.RemediationReview:
			if review {
				reviewed = append(reviewed, f)
			}
		}
	}
	if len(auto)+len(reviewed) == 0 {
		if review {
			fmt.Println("Nothing hostveil can fix. Manual findings are explained by `hostveil explain <id>`.")
		} else {
			fmt.Println("No auto-fixable findings. Nothing to do.")
		}
		return 0
	}

	if len(auto) > 0 {
		fmt.Printf("Will apply %d safe (Auto) fixes:\n", len(auto))
		for _, f := range auto {
			fmt.Printf("  • %s (%s) — %s\n", f.ID, f.Service, f.Title)
		}
	}
	if len(reviewed) > 0 {
		fmt.Printf("\nAnd %d Review fixes, each through its first alternative:\n", len(reviewed))
		for _, f := range reviewed {
			fmt.Printf("  • %s (%s) — %s\n", f.ID, f.Service, f.Title)
		}
		fmt.Println("\nThese are Review because they can cut off access to this host, or because")
		fmt.Println("they run a command with no checkpoint to undo. Read them before saying yes.")
	} else {
		fmt.Println("\nReview/Manual findings are left for you to handle individually.")
	}
	if !yes && !promptYesNo("Apply all of the above?") {
		fmt.Println("Aborted. Nothing changed.")
		return 0
	}

	batch := append(append([]model.Finding{}, auto...), reviewed...)
	apply := engine.ApplyBatch
	if review {
		apply = engine.ApplyBatchWithReviewed
	}
	out := apply(ctx, batch)
	// One sentence, rendered by the engine, so this and the other two
	// interfaces cannot describe the same outcome differently. Only the
	// per-failure detail and the rollback hint are the CLI's own — it has
	// the room for the first and is the only place the second is a command
	// you can type.
	fmt.Printf("\n✓ %s\n", out.Message)
	for id, msg := range out.Failed {
		fmt.Printf("  ✗ %s: %s\n", id, msg)
	}
	fmt.Println("Roll back any change with: hostveil history")
	if out.Interrupted {
		return 1
	}
	return 0
}

func findFinding(r model.Report, id, service string) (model.Finding, bool) {
	for _, f := range r.Findings {
		if f.Fixed || f.ID != id {
			continue
		}
		if service == "" || f.Service == service {
			return f, true
		}
	}
	return model.Finding{}, false
}

func resolveAction(p model.FixPreview, action int, yes bool) (int, error) {
	if len(p.Actions) == 1 {
		return 0, nil
	}
	if action >= 0 {
		if action >= len(p.Actions) {
			return 0, fmt.Errorf("action %d out of range (0..%d)", action, len(p.Actions)-1)
		}
		return action, nil
	}
	// Review fix with multiple alternatives and no explicit choice.
	fmt.Printf("This finding has %d alternatives:\n", len(p.Actions))
	for _, a := range p.Actions {
		fmt.Printf("  [%d] %s\n", a.Index, a.Label)
	}
	if yes {
		return 0, fmt.Errorf("multiple alternatives; re-run with --action N to pick one")
	}
	choice := prompt("Choose an alternative [0]: ")
	if choice == "" {
		return 0, nil
	}
	var n int
	if _, err := fmt.Sscanf(choice, "%d", &n); err != nil || n < 0 || n >= len(p.Actions) {
		return 0, fmt.Errorf("invalid choice %q", choice)
	}
	return n, nil
}

func printPreview(f model.Finding, p model.FixPreview, idx int) {
	a := p.Actions[idx]
	fmt.Printf("\nFix for %s (%s): %s\n", f.ID, f.Service, p.Label)
	fmt.Printf("Action: %s\n", a.Label)
	if a.Warning != "" {
		fmt.Printf("\n⚠  %s\n", a.Warning)
	}
	switch a.Type {
	case "edit", "mode":
		fmt.Printf("\n%s\n", a.Diff)
	case "exec":
		fmt.Println("\nThe following commands will run:")
		for _, cmd := range a.Commands {
			fmt.Printf("  $ %s\n", strings.Join(cmd, " "))
		}
		fmt.Println()
	default:
		// Never leave a confirmation prompt with nothing above it: an empty
		// preview beside a live "apply?" reads as "this changes nothing".
		fmt.Printf("\n(no preview available for action type %q)\n\n", a.Type)
	}
}

func printOutcome(o model.FixOutcome) {
	if !o.Success {
		fmt.Fprintln(os.Stderr, "Fix did not apply:", o.Error)
		return
	}
	fmt.Println("✓ Fix applied.")
	if o.CheckpointID != "" {
		fmt.Printf("  Rollback with: hostveil rollback %s\n", o.CheckpointID)
	} else {
		fmt.Println("  (This change is not file-based and cannot be auto-rolled-back.)")
	}
	if o.RestartHint != "" {
		fmt.Printf("  You may need to restart the '%s' service for the change to take effect.\n", o.RestartHint)
	}
	if o.VerifyMessage != "" {
		fmt.Printf("  %s\n", o.VerifyMessage)
		if o.VerifyNote != "" {
			fmt.Printf("    %s\n", o.VerifyNote)
		}
	}
	fmt.Printf("  New security score: %d/100\n", o.NewScore.Overall)
}

func serviceSuffix(service string) string {
	if service == "" {
		return ""
	}
	return " for service " + service
}

// stdin is the reader prompts consume, and it is package-level for two
// reasons.
//
// The first is correctness. This used to build a fresh bufio.Scanner around
// os.Stdin on every call, and a Scanner reads ahead into its own buffer — so
// asking two questions in a row (choose an alternative, then confirm) could
// read both answers into the first scanner and throw the second away with
// it, leaving the confirmation to consume EOF and read as "no". One reader
// for the process is what makes a sequence of prompts work.
//
// The second is that a command which cannot be given input cannot be tested,
// and `hostveil fix` is the most destructive thing this binary does.
var stdin io.Reader = os.Stdin

var promptIn *bufio.Reader

func prompt(msg string) string {
	fmt.Print(msg)
	if promptIn == nil {
		promptIn = bufio.NewReader(stdin)
	}
	line, err := promptIn.ReadString('\n')
	if line == "" && err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func promptYesNo(msg string) bool {
	ans := strings.ToLower(prompt(msg + " [y/N] "))
	return ans == "y" || ans == "yes"
}
