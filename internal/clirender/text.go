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
	fmt.Fprintf(&b, "\nSince last scan: %d resolved, %d new, %d still present.\n",
		len(d.Resolved), len(d.New), d.StillPresent)
	deltaLines(&b, "  ✓ resolved: ", d.Resolved)
	deltaLines(&b, "  + new: ", d.New)
	return b.String()
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
