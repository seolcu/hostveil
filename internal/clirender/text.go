// Package clirender renders a scan Report as text or JSON for the CLI.
// Keeping rendering here (rather than in cmd/) lets the CLI, and later any
// other text surface, share one formatting implementation.
package clirender

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/glyph"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/textwidth"
)

// Options controls text rendering.
type Options struct {
	Color   bool
	Verbose bool // include descriptions and fix guidance
	// Glyphs is which symbol set to draw the status markers from. The zero
	// value is glyph.Plain, so a caller that does not set it gets exactly
	// what this renderer printed before the field existed.
	Glyphs glyph.Set
}

// Text renders a human-readable report.
func Text(r model.Report, opts Options) string {
	var b strings.Builder
	c := palette(opts.Color)

	// No axis ran, so there is nothing to average and the number would be
	// arbitrary. Printing one anyway is the same lie the per-axis N/A exists
	// to prevent, in the one place everybody reads.
	if !r.Score.Applicable {
		fmt.Fprintf(&b, "%sSecurity score: %sN/A — no domain could be scanned%s\n\n", c.bold, c.dim, c.reset)
	} else {
		fmt.Fprintf(&b, "%sSecurity score: %s%d/100%s%s\n\n",
			c.bold, scoreColor(c, r.Score.Overall), r.Score.Overall, c.reset,
			afterFixes(c, r.Score.Applicable, r.Score.Overall, r.Score.AfterFixes))
	}

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
		fmt.Fprintf(&b, "  %-22s %3d/100  %s%s%s\n", ax.Label, ax.Score, counts, partial,
			afterFixes(c, ax.Applicable, ax.Score, ax.AfterFixes))
	}
	b.WriteString("\n")

	// Domain status (skipped/degraded/errored checkers). All three markers
	// come from the same set — they are printed as one block, and a patched
	// glyph on the skipped line beside an ASCII one on the partial line
	// reads as two different kinds of remark rather than three degrees of
	// the same one.
	for _, d := range r.Domains {
		switch d.State {
		case model.ScanSkipped:
			fmt.Fprintf(&b, "  %s%s %s skipped: %s%s\n", c.dim, opts.Glyphs.Of(glyph.Skipped), d.Source, d.Reason, c.reset)
		case model.ScanDegraded:
			fmt.Fprintf(&b, "  %s%s %s partial: %s%s\n", c.yellow, opts.Glyphs.Of(glyph.Partial), d.Source, d.Reason, c.reset)
		case model.ScanError:
			fmt.Fprintf(&b, "  %s%s %s error: %s%s\n", c.red, opts.Glyphs.Of(glyph.Failed), d.Source, d.Reason, c.reset)
		}
	}

	active := r.Select(model.Filter{})
	if len(active) == 0 {
		// "Clean" is a claim about the whole host, so it may only be made
		// when the whole host was actually examined.
		if n := r.IncompleteDomains(); n > 0 {
			fmt.Fprintf(&b, "\n%sNo problems found in the domains that ran — but %d did not complete (see above).%s\n",
				c.yellow, n, c.reset)
		} else {
			fmt.Fprintf(&b, "\n%sNo problems found. Clean.%s\n", c.green, c.reset)
		}
		return b.String()
	}

	fmt.Fprintf(&b, "\n%sFindings (%d):%s\n\n", c.bold, len(active), c.reset)
	for i, f := range active {
		// A blank line between entries only earns its space when an entry is
		// more than one line. Verbose adds a description and fix guidance
		// under each headline, so there the separator is what keeps two
		// findings from reading as one paragraph; the plain listing is a
		// table, and double-spacing it made a routine 86-finding host four
		// screens of scrollback instead of two.
		if opts.Verbose && i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  %s[%s]%s %s  %s%s%s",
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

	auto := len(model.AutoFixable(active))

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
//
// It takes the whole Options rather than just the glyph set so it cannot
// drift out of step with Text's: the two are printed one after the other and
// a resolved-tick from a different table in the middle of one report would
// be the only place hostveil disagreed with itself about a symbol.
func DeltaSummary(d model.Delta, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nSince last scan: %d resolved, %d new, %d changed, %d still present.\n",
		len(d.Resolved), len(d.New), len(d.Changed), d.StillPresent)
	deltaLines(&b, "  "+opts.Glyphs.Of(glyph.OK)+" resolved: ", d.Resolved)
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

// severityCounts renders an axis's mix. It walks ScoreAxis.Counts, which is
// ordered most-severe-first by the model, rather than naming the levels — a
// hand-written arm per level is what had to be edited in three renderers when
// the scale changed.
func severityCounts(ax model.ScoreAxis) string {
	var parts []string
	for _, c := range ax.Counts {
		if c.N > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c.N, c.Severity))
		}
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, ", ")
}

type colors struct {
	bold, dim, reset, red, green, yellow, orange string
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

// sevColor is the heat a severity is drawn in. Orange is not used: it is the
// score band's colour (BandPoor), and it stopped being a severity's when the
// top two levels merged. Three levels, three heats, and nothing has to invent
// a fourth.
func sevColor(c colors, s model.Severity) string {
	switch s {
	case model.SeverityHigh:
		return c.red
	case model.SeverityMedium:
		return c.yellow
	default:
		return c.dim
	}
}

func scoreColor(c colors, score uint8) string {
	switch model.BandFor(score) {
	case model.BandGood:
		return c.green
	case model.BandFair:
		return c.yellow
	case model.BandPoor:
		return c.orange
	default:
		return c.red
	}
}

// wrap reflows text to width columns, indenting continuation lines.
// wrap reflows text to width display columns, indenting continuation lines.
//
// The count is columns rather than bytes. Counting bytes wrapped Hangul at
// roughly two-thirds of the width it was given, and the TUI's copy of this
// function had the same flaw — which is why there is now one of it.
func wrap(s string, width int, indent string) string {
	return textwidth.Wrap(s, width, minWrapWidth, indent)
}

// minWrapWidth is the floor for a computed width; one word per line is
// unreadable in a way an overrun is not.
const minWrapWidth = 8

// afterFixes renders the headroom note, or nothing.
//
// Nothing is the common case and it has to stay that way: an arrow pointing
// at the number it starts from is noise on every clean host, and a number
// beside an N/A axis is a claim about a domain nobody looked at. The three
// UIs each own their own formatting and all three answer these two questions
// the same way — TestEveryUIHidesAfterFixesTheSameWay pins that.
func afterFixes(c colors, applicable bool, score, after uint8) string {
	if !applicable || after <= score {
		return ""
	}
	return fmt.Sprintf("%s  → %d after fixes%s", c.dim, after, c.reset)
}
