package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

func cmdFix(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	var (
		service string
		action  int
		yes     bool
		all     bool
	)
	fs.StringVar(&service, "service", "", "disambiguate a finding by service name")
	fs.IntVar(&action, "action", -1, "for Review fixes, the alternative to apply (0-based)")
	fs.BoolVar(&yes, "yes", false, "apply without an interactive confirmation")
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
		return fixAll(ctx, yes)
	}
	if findingID == "" {
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "usage: hostveil fix <finding-id> [--service NAME] [--action N] [--yes]")
			return 2
		}
		findingID = fs.Arg(0)
	}

	engine := buildEngine()
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
func fixAll(ctx context.Context, yes bool) int {
	engine := buildEngine()
	report := engine.Scan(ctx, nil)

	var auto []model.Finding
	for _, f := range report.Findings {
		if !f.Fixed && f.Remediation == model.RemediationAuto {
			auto = append(auto, f)
		}
	}
	if len(auto) == 0 {
		fmt.Println("No auto-fixable findings. Nothing to do.")
		return 0
	}

	fmt.Printf("Will apply %d safe (Auto) fixes:\n", len(auto))
	for _, f := range auto {
		fmt.Printf("  • %s (%s) — %s\n", f.ID, f.Service, f.Title)
	}
	fmt.Println("\nReview/Manual findings are left for you to handle individually.")
	if !yes && !promptYesNo("Apply all of the above?") {
		fmt.Println("Aborted. Nothing changed.")
		return 0
	}

	out := engine.ApplyBatch(ctx, auto)
	fmt.Printf("\n✓ Applied %d fixes", len(out.Applied))
	if len(out.Failed) > 0 {
		fmt.Printf(", %d failed", len(out.Failed))
	}
	fmt.Printf(". New security score: %d/100\n", out.NewScore.Overall)
	for id, msg := range out.Failed {
		fmt.Printf("  ✗ %s: %s\n", id, msg)
	}
	fmt.Println("Roll back any change with: hostveil history")
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
	fmt.Printf("  New security score: %d/100\n", o.NewScore.Overall)
}

func serviceSuffix(service string) string {
	if service == "" {
		return ""
	}
	return " for service " + service
}

func prompt(msg string) string {
	fmt.Print(msg)
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text())
	}
	return ""
}

func promptYesNo(msg string) bool {
	ans := strings.ToLower(prompt(msg + " [y/N] "))
	return ans == "y" || ans == "yes"
}
