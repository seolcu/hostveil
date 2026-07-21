// Package clirender renders a scan Report as text or JSON for the CLI.
// Keeping rendering here (rather than in cmd/) lets the CLI, and later any
// other text surface, share one formatting implementation.
package clirender

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// Options controls text rendering.
type Options struct {
	Color   bool
	Verbose bool // include descriptions and fix guidance
}

// Text renders a human-readable report.
func Text(r model.Report, opts Options) string {
	var b strings.Builder
	c := palette(opts.Color)

	fmt.Fprintf(&b, "%sSecurity score: %s%d/100%s\n\n", c.bold, scoreColor(c, r.Score.Overall), r.Score.Overall, c.reset)

	for _, ax := range r.Score.Axes {
		if !ax.Applicable {
			fmt.Fprintf(&b, "  %-22s %s%s%s\n", ax.Label, c.dim, "N/A (not run)", c.reset)
			continue
		}
		counts := severityCounts(ax)
		// A degraded axis is scored from an incomplete picture, so it is
		// marked: an unlabelled score here reads as a clean result.
		partial := ""
		if ax.Degraded {
			partial = c.yellow + " (partial)" + c.reset
		}
		fmt.Fprintf(&b, "  %-22s %3d/100  %s%s\n", ax.Label, ax.Score, counts, partial)
	}
	b.WriteString("\n")

	// Domain status (skipped/degraded/errored checkers).
	for _, d := range r.Domains {
		switch d.State {
		case model.ScanSkipped:
			fmt.Fprintf(&b, "  %s· %s skipped: %s%s\n", c.dim, d.Source, d.Reason, c.reset)
		case model.ScanDegraded:
			fmt.Fprintf(&b, "  %s~ %s partial: %s%s\n", c.yellow, d.Source, d.Reason, c.reset)
		case model.ScanError:
			fmt.Fprintf(&b, "  %s! %s error: %s%s\n", c.red, d.Source, d.Reason, c.reset)
		}
	}

	active := r.Select(model.Filter{})
	if len(active) == 0 {
		// "Clean" is a claim about the whole host, so it may only be made
		// when the whole host was actually examined.
		if n := incompleteDomains(r); n > 0 {
			fmt.Fprintf(&b, "\n%sNo problems found in the domains that ran — but %d did not complete (see above).%s\n",
				c.yellow, n, c.reset)
		} else {
			fmt.Fprintf(&b, "\n%sNo problems found. Clean.%s\n", c.green, c.reset)
		}
		return b.String()
	}

	fmt.Fprintf(&b, "\n%sFindings (%d):%s\n", c.bold, len(active), c.reset)
	for _, f := range active {
		fmt.Fprintf(&b, "\n  %s[%s]%s %s  %s%s%s",
			sevColor(c, f.Severity), strings.ToUpper(f.Severity.String()), c.reset,
			f.ID, c.bold, f.Title, c.reset)
		if f.Service != "" {
			fmt.Fprintf(&b, " %s(%s)%s", c.dim, f.Service, c.reset)
		}
		fmt.Fprintf(&b, " %s%s%s\n", c.dim, f.Remediation.Label(), c.reset)
		if opts.Verbose {
			if f.Description != "" {
				fmt.Fprintf(&b, "      %s\n", wrap(f.Description, 72, "      "))
			}
			if f.HowToFix != "" {
				fmt.Fprintf(&b, "      %sFix:%s %s\n", c.green, c.reset, wrap(f.HowToFix, 72, "      "))
			}
		}
	}
	b.WriteString(nextSteps(active, opts))
	return b.String()
}

// nextSteps closes the report with the commands that act on what it just
// listed.
//
// The report used to end at the last finding. It named a remediation kind
// per finding — "Auto", "Review", "Manual" — without ever naming the command
// that acts on one, so a first-time user was shown a score, a list of
// problems, and no way in. `fix --all` already closes with a next step; the
// primary output path, the one everybody sees first, was the one without.
func nextSteps(active []model.Finding, opts Options) string {
	if len(active) == 0 {
		return ""
	}
	c := palette(opts.Color)

	auto := 0
	for _, f := range active {
		if f.Remediation == model.RemediationAuto {
			auto++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n%sNext:%s\n", c.bold, c.reset)
	if auto > 0 {
		// Named before the per-finding commands because it is the one action
		// that needs no decision: every Auto fix is reversible, cannot cut
		// off access to the host, and has exactly one correct form.
		fmt.Fprintf(&b, "  %shostveil fix --all%s        apply the %d safe fix(es) — each is previewed and reversible\n",
			c.green, c.reset, auto)
	}
	fmt.Fprintf(&b, "  %shostveil explain <id>%s     what a finding means and why it matters\n", c.green, c.reset)
	fmt.Fprintf(&b, "  %shostveil fix <id>%s         preview one fix and apply it after confirming\n", c.green, c.reset)
	if !opts.Verbose {
		fmt.Fprintf(&b, "  %shostveil scan -v%s          show every finding's description and fix guidance\n", c.green, c.reset)
	}
	return b.String()
}

// maxDeltaLines bounds how many changed findings DeltaSummary names. A
// "short summary" that lists every change is not short: bringing up one new
// stack already produces hundreds of lines, and a release that changes how a
// domain represents its findings can retire thousands of keys at once.
const maxDeltaLines = 10

// DeltaSummary renders a short "since last scan" summary line.
func DeltaSummary(d model.Delta) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nSince last scan: %d resolved, %d new, %d changed, %d still present.\n",
		len(d.Resolved), len(d.New), len(d.Changed), d.StillPresent)
	deltaLines(&b, "  ✓ resolved: ", d.Resolved)
	deltaLines(&b, "  + new: ", d.New)
	changedLines(&b, d.Changed)
	return b.String()
}

// maxChangedValue bounds how long an evidence value may be before it is
// summarised rather than printed. An aggregate finding can carry thousands
// of IDs in one value; the point of the line is what moved, not the payload.
const maxChangedValue = 40

// changedLines names findings that persisted but moved, and says how. A bare
// "changed" is not actionable — the useful part is "count 3627 → 3630".
func changedLines(b *strings.Builder, cs []model.FindingChange) {
	shown := cs
	if len(shown) > maxDeltaLines {
		shown = shown[:maxDeltaLines]
	}
	for _, c := range shown {
		fmt.Fprintf(b, "  ~ changed: %s (%s)%s\n", c.Current.ID, c.Current.Service, changeDetail(c))
	}
	if rest := len(cs) - len(shown); rest > 0 {
		fmt.Fprintf(b, "  ~ changed: … and %d more\n", rest)
	}
}

func changeDetail(c model.FindingChange) string {
	var parts []string
	if c.Previous.Severity != c.Current.Severity {
		parts = append(parts, fmt.Sprintf("severity %s → %s",
			strings.ToLower(c.Previous.Severity.String()), strings.ToLower(c.Current.Severity.String())))
	}
	for _, k := range c.ChangedEvidence() {
		before, after := c.Previous.Evidence[k], c.Current.Evidence[k]
		if len(before) <= maxChangedValue && len(after) <= maxChangedValue {
			parts = append(parts, fmt.Sprintf("%s %s → %s", k, orNone(before), orNone(after)))
			continue
		}
		// Too long to show whole — it is a list (the "a, b, c" convention
		// checkers use for multi-item evidence), so report what entered and
		// left it instead of the payload.
		parts = append(parts, k+" "+membership(c.EvidenceListDelta(k)))
	}
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, ", ")
}

// maxNamedItems bounds how many list members are named per direction.
const maxNamedItems = 5

// membership renders "+3 (CVE-A, CVE-B, CVE-C), -1 (CVE-X)".
func membership(added, removed []string) string {
	var parts []string
	if len(added) > 0 {
		parts = append(parts, fmt.Sprintf("+%d (%s)", len(added), nameSome(added)))
	}
	if len(removed) > 0 {
		parts = append(parts, fmt.Sprintf("-%d (%s)", len(removed), nameSome(removed)))
	}
	if len(parts) == 0 {
		// The value moved without its membership doing so — reordered, or
		// reformatted. Say that rather than claiming a change we cannot show.
		return "changed"
	}
	return strings.Join(parts, ", ")
}

func nameSome(items []string) string {
	if len(items) <= maxNamedItems {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(items[:maxNamedItems], ", "), len(items)-maxNamedItems)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// deltaLines names up to maxDeltaLines findings and always says how many it
// left out. Silently truncating would read as "that was all of them".
func deltaLines(b *strings.Builder, prefix string, fs []model.Finding) {
	shown := fs
	if len(shown) > maxDeltaLines {
		shown = shown[:maxDeltaLines]
	}
	for _, f := range shown {
		fmt.Fprintf(b, "%s%s (%s)\n", prefix, f.ID, f.Service)
	}
	if rest := len(fs) - len(shown); rest > 0 {
		fmt.Fprintf(b, "%s… and %d more\n", prefix, rest)
	}
}

// JSON renders the report as indented JSON.
func JSON(r model.Report) (string, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func severityCounts(ax model.ScoreAxis) string {
	var parts []string
	if ax.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", ax.Critical))
	}
	if ax.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", ax.High))
	}
	if ax.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", ax.Medium))
	}
	if ax.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", ax.Low))
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, ", ")
}

type colors struct {
	bold, dim, reset, red, green, yellow, orange string
}

// incompleteDomains counts domains that did not fully cover their ground —
// skipped, degraded, or errored.
func incompleteDomains(r model.Report) int {
	n := 0
	for _, d := range r.Domains {
		if d.State != model.ScanDone {
			n++
		}
	}
	return n
}

func palette(on bool) colors {
	if !on {
		return colors{}
	}
	return colors{
		bold:   "\x1b[1m",
		dim:    "\x1b[2m",
		reset:  "\x1b[0m",
		red:    "\x1b[31m",
		green:  "\x1b[32m",
		yellow: "\x1b[33m",
		orange: "\x1b[38;5;208m",
	}
}

func sevColor(c colors, s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return c.red
	case model.SeverityHigh:
		return c.orange
	case model.SeverityMedium:
		return c.yellow
	default:
		return c.dim
	}
}

func scoreColor(c colors, score uint8) string {
	switch {
	case score >= 80:
		return c.green
	case score >= 50:
		return c.yellow
	default:
		return c.red
	}
}

// wrap reflows text to width columns, indenting continuation lines.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if i > 0 && lineLen+1+len(w) > width {
			b.WriteString("\n" + indent)
			lineLen = 0
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}
