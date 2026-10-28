package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/seolcu/hostveil/internal/platform"
	"github.com/seolcu/hostveil/internal/triage"
)

// cmdTriage collects a read-only evidence bundle and says whether it shows
// a compromise. `triage verify DIR` re-hashes a bundle; `triage analyze DIR`
// re-derives its conclusions without touching it.
func cmdTriage(ctx context.Context, args []string) int {
	if len(args) > 0 && (args[0] == "verify" || args[0] == "analyze") {
		if len(args) != 2 {
			fmt.Fprintf(os.Stderr, "usage: hostveil triage %s <bundle-dir>\n", args[0])
			return 2
		}
		if args[0] == "verify" {
			return triageVerify(args[1])
		}
		res, m, err := triage.Analyze(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostveil:", err)
			return 1
		}
		fmt.Print(triage.Report(res, m))
		return 0
	}

	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	var out, since string
	fs.StringVar(&out, "out", "", "write the evidence bundle to DIR (default ./hostveil-triage-<host>-<time>); put it on another disk if you can")
	fs.StringVar(&since, "since", "30d", "how far back to read logs and file changes, e.g. 7d, 90d, 48h")
	if code := parseAndElevate(fs, args); code >= 0 {
		return code
	}
	if ok, why := platform.AuditableOS(); !ok {
		fmt.Fprintln(os.Stderr, "hostveil:", why)
		return 2
	}
	window, err := parseSince(since)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 2
	}
	now := time.Now()
	if out == "" {
		h, _ := os.Hostname()
		out = fmt.Sprintf("hostveil-triage-%s-%s", h, now.UTC().Format("20060102T150405Z"))
	}
	if sameFilesystem(out, "/") {
		fmt.Fprintln(os.Stderr, "hostveil: note: the bundle is being written to the filesystem under examination. "+
			"That is fine for a first look; for evidence you may need to show someone, write it to another disk with --out.")
	}

	// Collection runs commands that read the whole system, so they get
	// minutes rather than the scan's seconds, and room for large outputs.
	runner := platform.DefaultRunner{Timeout: 10 * time.Minute, MaxOutput: 512 << 20}
	env := platform.Detect(ctx, runner)
	exe, _ := os.Executable()
	fmt.Fprintln(os.Stderr, "Collecting evidence (read-only)… this reads every installed file once and can take a few minutes.")
	res, m, seal, err := triage.Run(ctx, triage.Options{
		Out: out, Since: window, Root: "/", Version: version, Exe: exe,
		Now: time.Now,
	}, env)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	c := res.Counts()
	fmt.Printf("Bundle: %s (%d artifacts)\n", out, len(m.Artifacts))
	fmt.Printf("Compromise: %d   Suspicious: %d   Attempt: %d   Evidence gaps: %d\n",
		c[triage.Compromise], c[triage.Suspicious], c[triage.Attempt], len(res.Gaps))
	for _, in := range res.Indicators {
		if in.Verdict != triage.Attempt {
			fmt.Printf("  %-10s %s (%s)\n", in.Verdict, in.Title, in.ID)
		}
	}
	fmt.Printf("\nRead %s/report.md for the evidence behind each.\n", out)
	fmt.Printf("Manifest SHA-256: %s\n", seal)
	fmt.Println("Write that hash down somewhere this host cannot reach: it is what proves later that the bundle was not changed.")
	if c[triage.Compromise] > 0 {
		return 3
	}
	return 0
}

func triageVerify(dir string) int {
	v, err := triage.Verify(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	fmt.Printf("Checked %d files. Manifest SHA-256: %s\n", v.Checked, v.Seal)
	for _, p := range v.Mismatch {
		fmt.Println("  CHANGED  " + p)
	}
	for _, p := range v.Missing {
		fmt.Println("  MISSING  " + p)
	}
	for _, p := range v.Extra {
		fmt.Println("  EXTRA    " + p)
	}
	if !v.OK() {
		fmt.Println("The bundle does not match its manifest.")
		return 1
	}
	fmt.Println("Every file matches its manifest. Compare the manifest hash with the one recorded at collection.")
	return 0
}

// parseSince reads "30d", "2w" or a Go duration.
func parseSince(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, ok := strings.CutSuffix(s, suffix); ok {
			v, err := strconv.Atoi(n)
			if err != nil || v <= 0 {
				return 0, fmt.Errorf("--since %q: want a positive number of days or weeks, e.g. 30d", s)
			}
			return time.Duration(v) * unit, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--since %q: want e.g. 30d, 2w or 48h", s)
	}
	return d, nil
}

// sameFilesystem reports whether path (or the directory it will be made
// in) is on the same device as ref.
func sameFilesystem(path, ref string) bool {
	dir := path
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		next := dir[:max(0, strings.LastIndex(dir, "/"))]
		if next == "" || next == dir {
			dir = "."
			break
		}
		dir = next
	}
	var a, b syscall.Stat_t
	if syscall.Stat(dir, &a) != nil || syscall.Stat(ref, &b) != nil {
		return false
	}
	return a.Dev == b.Dev
}
