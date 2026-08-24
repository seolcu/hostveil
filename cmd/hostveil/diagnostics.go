package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/diagnostics"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
	"github.com/seolcu/hostveil/internal/selfupdate"
)

// cmdDiagnostics never touches the network. It used to also offer to open
// the bundle as a GitHub issue (`bugreport --send`), which meant hostveil
// itself decided when and how a report left the host; the network path was
// removed rather than fixed because a self-hosted-server tool's own audience
// is the one most likely to distrust that decision being made for them. What
// is left is the part nobody objected to: collecting the pieces a human
// would otherwise have to gather by hand before filing an issue.
func cmdDiagnostics(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("diagnostics", flag.ContinueOnError)
	var (
		trace      string
		unredacted bool
		output     string
	)
	fs.StringVar(&trace, "trace", "", "attach a HOSTVEIL_DEBUG=1 command trace file")
	fs.BoolVar(&unredacted, "unredacted", false, "skip redacting IPs and usernames (local use only)")
	fs.StringVar(&output, "output", "", "write the report to a file instead of printing it")
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}

	bundle, err := buildDiagnosticsReport(diagnosticsOptions{trace: trace, redact: !unredacted})
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}

	if output != "" {
		if err := writeReport(output, []byte(bundle)); err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		fmt.Println("Wrote", output)
		return 0
	}

	fmt.Print(bundle)
	fmt.Printf("\nAttach this to a new issue at https://github.com/%s/issues/new if you're filing a bug report.\n", selfupdate.Repo)
	return 0
}

type diagnosticsOptions struct {
	trace  string
	redact bool
}

// buildDiagnosticsReport assembles hostveil's own identity, recent crash
// records, the last saved scan's score and per-finding IDs/severities/domain
// states — deliberately never the full description, remediation text, or
// evidence a finding carries, which can quote the very config an operator is
// asking for help with — and an optional HOSTVEIL_DEBUG trace the operator
// already produced by hand. See --help's Environment section for that
// workflow; this command is the packaging step for it, not a replacement.
func buildDiagnosticsReport(opts diagnosticsOptions) (string, error) {
	var b strings.Builder
	fmt.Fprintln(&b, "# hostveil diagnostics")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- hostveil: %s\n", version)
	fmt.Fprintf(&b, "- go: %s\n", runtime.Version())
	fmt.Fprintf(&b, "- os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	env := platform.Detect(context.Background(), platform.DefaultRunner{})
	distro := env.DistroID
	if distro == "" {
		distro = "unknown"
	}
	fmt.Fprintf(&b, "- distro: %s\n", distro)
	fmt.Fprintf(&b, "- package manager: %s\n", env.PackageManager)
	fmt.Fprintf(&b, "- service manager: %s\n", env.ServiceManager)
	fmt.Fprintln(&b)

	writeCrashes(&b)
	writeScanSummary(&b)

	if opts.trace != "" {
		// A path the operator named on their own command line, pointed at a
		// file they were already told to produce by hand — the same trust
		// boundary as --output on every other subcommand.
		data, err := os.ReadFile(opts.trace)
		if err != nil {
			return "", fmt.Errorf("reading --trace %s: %w", opts.trace, err)
		}
		fmt.Fprintf(&b, "## Command trace (%s)\n\n```\n%s\n```\n", opts.trace, strings.TrimSpace(string(data)))
	}

	out := b.String()
	if opts.redact {
		out = diagnostics.Redact(out)
	}
	return out, nil
}

func writeCrashes(b *strings.Builder) {
	crashes, _ := diagnostics.Crashes(history.DefaultDir(), 5)
	fmt.Fprintln(b, "## Recent crashes")
	if len(crashes) == 0 {
		fmt.Fprintln(b, "\nNone recorded.")
		fmt.Fprintln(b)
		return
	}
	for _, c := range crashes {
		fmt.Fprintf(b, "\n### %s — %s (%s)\n\n```\n%s\n%s\n```\n",
			c.At.Format(time.RFC3339), c.Command, c.Where, c.Panic, c.Stack)
	}
	fmt.Fprintln(b)
}

func writeScanSummary(b *strings.Builder) {
	fmt.Fprintln(b, "## Last saved scan")
	data, ok, err := history.NewStore(history.DefaultDir()).LastReport()
	if err != nil || !ok {
		fmt.Fprintln(b, "\nNo saved scan yet.")
		fmt.Fprintln(b)
		return
	}
	var r model.Report
	if json.Unmarshal(data, &r) != nil {
		fmt.Fprintln(b, "\n(could not read the last saved scan)")
		fmt.Fprintln(b)
		return
	}

	if r.Score.Applicable {
		fmt.Fprintf(b, "\nScore: %d/100\n", r.Score.Overall)
	} else {
		fmt.Fprintln(b, "\nScore: N/A")
	}

	fmt.Fprintln(b, "\nDomains:")
	for _, d := range r.Domains {
		fmt.Fprintf(b, "- %s: %s", d.Source, d.State)
		if d.Reason != "" {
			fmt.Fprintf(b, " (%s)", d.Reason)
		}
		fmt.Fprintln(b)
	}

	fmt.Fprintln(b, "\nFindings (id, severity, service — no description or evidence):")
	if len(r.Findings) == 0 {
		fmt.Fprintln(b, "- none")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(b, "- %s  %s", f.ID, f.Severity)
		if f.Service != "" {
			fmt.Fprintf(b, "  service=%s", f.Service)
		}
		fmt.Fprintln(b)
	}
	fmt.Fprintln(b)
}
