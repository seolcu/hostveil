package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/diagnostics"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
	"github.com/seolcu/hostveil/internal/selfupdate"
)

func cmdBugreport(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("bugreport", flag.ContinueOnError)
	var (
		trace      string
		unredacted bool
		send       bool
		yes        bool
		output     string
	)
	fs.StringVar(&trace, "trace", "", "attach a HOSTVEIL_DEBUG=1 command trace file")
	fs.BoolVar(&unredacted, "unredacted", false, "skip redacting IPs and usernames (local use only; refuses --send)")
	fs.BoolVar(&send, "send", false, "offer to open the report as a GitHub issue")
	fs.BoolVar(&yes, "yes", false, "skip the confirmation prompt (--send is still required to transmit anything)")
	fs.StringVar(&output, "output", "", "write the report to a file instead of printing it")
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}
	if unredacted && send {
		fmt.Fprintln(os.Stderr, "hostveil: --unredacted refuses to combine with --send")
		return 2
	}

	bundle, err := buildBugReport(bugreportOptions{trace: trace, redact: !unredacted})
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}

	if output != "" {
		// bugreport auto-elevates to read the system state directory. Use the
		// same writer as scan --output so a newly created report is handed
		// back to the invoking user instead of being left root-owned.
		if err := writeReport(output, []byte(bundle)); err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		fmt.Println("Wrote", output)
	} else {
		fmt.Print(bundle)
	}

	if !send {
		fmt.Println("Nothing was sent. Re-run with --send to offer to open this as a GitHub issue.")
		return 0
	}
	if !yes && !promptYesNo(fmt.Sprintf("\nSend this to https://github.com/%s/issues as a new issue?", selfupdate.Repo)) {
		fmt.Println("Not sent.")
		return 0
	}
	if err := sendBugReport(ctx, bundle); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	return 0
}

type bugreportOptions struct {
	trace  string
	redact bool
}

// buildBugReport assembles everything local before anything is offered to
// send: hostveil's own identity, recent crash records, the last saved scan's
// score and per-finding IDs/severities/domain states — deliberately never the
// full description, remediation text, or evidence a finding carries, which
// can quote the very config an operator is asking for help with — and an
// optional HOSTVEIL_DEBUG trace the operator already produced by hand. See
// --help's Environment section for that workflow; this command is the
// packaging step for it, not a replacement.
func buildBugReport(opts bugreportOptions) (string, error) {
	var b strings.Builder
	fmt.Fprintln(&b, "# hostveil bug report")
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

// sendBugReport is the only place in this command that reaches the network,
// and it only runs after the report has already been built locally and the
// operator has confirmed --send. It tries, in order, a personal access token
// and an already-authenticated gh CLI. A failed credential or network path is
// not allowed to lose the report: every failure ends at a local file the
// invoking user can read and paste by hand.
func sendBugReport(ctx context.Context, bundle string) error {
	var failures []string
	if token := os.Getenv("HOSTVEIL_GITHUB_TOKEN"); token != "" {
		if err := sendViaGitHubAPI(ctx, token, bundle); err == nil {
			return nil
		} else {
			failures = append(failures, "GitHub API: "+err.Error())
		}
	}
	if ghPath, err := exec.LookPath("gh"); err == nil {
		if err := sendViaGH(ctx, ghPath, bundle); err == nil {
			return nil
		} else {
			failures = append(failures, "GitHub CLI: "+err.Error())
		}
	}

	// The process is normally root here because bugreport needs to read
	// /var/lib/hostveil. Saving back into that directory made the advertised
	// fallback inaccessible to the person who ran the command. The current
	// directory is the one place the operator already selected, and
	// writeReport transfers a newly created file to SUDO_UID/SUDO_GID.
	p := "hostveil-bugreport.md"
	if err := writeReport(p, []byte(bundle)); err != nil {
		if len(failures) == 0 {
			return fmt.Errorf("saving unsent report to %s: %w", p, err)
		}
		return fmt.Errorf("sending failed (%s); saving %s: %w", strings.Join(failures, "; "), p, err)
	}
	if len(failures) > 0 {
		fmt.Println("Could not open the GitHub issue:", strings.Join(failures, "; "))
	} else {
		fmt.Println("Nothing to send with — set HOSTVEIL_GITHUB_TOKEN or install the GitHub CLI (gh).")
	}
	fmt.Printf("Saved the report to %s; open https://github.com/%s/issues/new and paste it in.\n", p, selfupdate.Repo)
	return nil
}

func sendViaGH(ctx context.Context, ghPath, bundle string) error {
	// G204: ghPath came back from exec.LookPath, and every argument is
	// a fixed literal — no operator input reaches argv. The report goes over
	// stdin rather than a root-owned temp file, which the invoking user's gh
	// process could not read after privileges are dropped below.
	//nolint:gosec // G204: resolved executables and fixed argv, by design
	args := []string{"issue", "create", "--repo", selfupdate.Repo,
		"--title", "hostveil bug report", "--body-file", "-"}
	program, argv := githubCLIInvocation(ghPath, args, os.Geteuid(), os.Getenv, exec.LookPath)
	cmd := exec.CommandContext(ctx, program, argv...)
	cmd.Stdin = strings.NewReader(bundle)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// githubCLIInvocation returns the process and argv used for gh. bugreport is
// normally a sudo child so running gh directly would look in /root for its
// authentication and report that the already-authenticated operator is not
// logged in. Root can safely run the resolved gh binary as SUDO_USER without
// another password prompt; -H points gh back at that user's config directory.
func githubCLIInvocation(ghPath string, args []string, euid int, getenv func(string) string, lookPath func(string) (string, error)) (string, []string) {
	if euid == 0 && getenv("SUDO_UID") != "" {
		if invoking := getenv("SUDO_USER"); invoking != "" && invoking != "root" {
			if sudoPath, err := lookPath("sudo"); err == nil {
				sudoArgs := []string{"-H", "-u", invoking, "--", ghPath}
				return sudoPath, append(sudoArgs, args...)
			}
		}
	}
	return ghPath, args
}

func sendViaGitHubAPI(ctx context.Context, token, bundle string) error {
	payload, err := json.Marshal(map[string]string{
		"title": "hostveil bug report",
		"body":  bundle,
	})
	if err != nil {
		return err
	}
	url := "https://api.github.com/repos/" + selfupdate.Repo + "/issues"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("GitHub returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var created struct {
		HTMLURL string `json:"html_url"`
	}
	if json.NewDecoder(resp.Body).Decode(&created) == nil && created.HTMLURL != "" {
		fmt.Println("Opened", created.HTMLURL)
	} else {
		fmt.Println("Issue created.")
	}
	return nil
}
