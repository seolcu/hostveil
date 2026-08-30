package report

import (
	"fmt"
	"strings"
)

// markdown renders d as GitHub-flavored Markdown: a header, then one section
// per Section, findings grouped severity-first with their evidence as a
// table. Paragraphs are written unwrapped — Markdown renderers reflow their
// own text, and a hard wrap here would fight that.
func markdown(d Doc) ([]byte, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	b.WriteString("Generated " + d.Generated.Format("2006-01-02 15:04 MST") + " by hostveil " + d.Version)
	if d.Hostname != "" {
		b.WriteString(" on `" + d.Hostname + "`")
	}
	b.WriteString(".\n\n")

	for _, sec := range d.Sections {
		writeMDSection(&b, sec)
	}

	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "*hostveil %s — generated %s. No AI was used to produce this report; "+
		"every explanation above comes directly from the finding hostveil detected.*\n",
		d.Version, d.Generated.Format("2006-01-02 15:04 MST"))

	return []byte(b.String()), nil
}

func writeMDSection(b *strings.Builder, sec Section) {
	if sec.Heading != "" {
		fmt.Fprintf(b, "%s %s\n\n", strings.Repeat("#", sec.Level+1), sec.Heading)
	}
	for _, p := range sec.Paragraphs {
		b.WriteString(p + "\n\n")
	}
	for _, kv := range sec.KV {
		fmt.Fprintf(b, "- **%s** — %s\n", kv.Key, kv.Value)
	}
	if len(sec.KV) > 0 {
		b.WriteString("\n")
	}
	if sec.Table != nil {
		writeMDTable(b, *sec.Table)
	}
	for _, f := range sec.Findings {
		writeMDFinding(b, f)
	}
}

func writeMDTable(b *strings.Builder, t Table) {
	if len(t.Headers) == 0 {
		return
	}
	b.WriteString("| " + strings.Join(t.Headers, " | ") + " |\n")
	b.WriteString("|" + strings.Repeat(" --- |", len(t.Headers)) + "\n")
	for _, row := range t.Rows {
		b.WriteString("| " + strings.Join(mdEscapeRow(row), " | ") + " |\n")
	}
	b.WriteString("\n")
}

func mdEscapeRow(row []string) []string {
	out := make([]string, len(row))
	for i, c := range row {
		out[i] = strings.ReplaceAll(c, "|", "\\|")
	}
	return out
}

func writeMDFinding(b *strings.Builder, f FindingBlock) {
	fmt.Fprintf(b, "#### %s\n\n", f.Title)
	fmt.Fprintf(b, "- **Domain:** %s", f.Domain)
	if f.Service != "" {
		fmt.Fprintf(b, " (%s)", f.Service)
	}
	b.WriteString("\n")
	fmt.Fprintf(b, "- **Remediation:** %s\n\n", f.RemediationLabel)

	if f.Description != "" {
		fmt.Fprintf(b, "**What this means.** %s\n\n", f.Description)
	}
	switch {
	case f.HowToFix != "":
		fmt.Fprintf(b, "**How to fix it.** %s\n\n", f.HowToFix)
	case f.WhyNoFix != "":
		fmt.Fprintf(b, "**Why hostveil won't do this for you.** %s\n\n", f.WhyNoFix)
	}
	if f.FixBenefit != "" {
		fmt.Fprintf(b, "**Benefit.** %s\n\n", f.FixBenefit)
	}
	if f.FixSideEffect != "" {
		fmt.Fprintf(b, "**Side effect.** %s\n\n", f.FixSideEffect)
	}
	if len(f.Evidence) > 0 {
		b.WriteString("**Evidence**\n\n")
		writeMDTable(b, Table{Headers: []string{"Key", "Value"}, Rows: kvRows(f.Evidence)})
	}
}

func kvRows(kvs []KV) [][]string {
	rows := make([][]string, len(kvs))
	for i, kv := range kvs {
		rows[i] = []string{kv.Key, kv.Value}
	}
	return rows
}
