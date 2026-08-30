package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// buildDoc turns a completed scan into the shared report structure every
// rich renderer walks. It is the one place model.Report/model.Finding are
// read for report purposes - Markdown, DOCX, and PDF never touch model
// directly.
func buildDoc(r model.Report, version string) Doc {
	hostname, _ := os.Hostname()
	d := Doc{
		Title:     "hostveil security report",
		Generated: time.Now().UTC(),
		Version:   version,
		Hostname:  hostname,
	}

	d.Sections = append(d.Sections, scoreSection(r.Score))
	d.Sections = append(d.Sections, domainsScoreSection(r.Score))
	d.Sections = append(d.Sections, domainsScannedSection(r.Domains))
	d.Sections = append(d.Sections, severityLegendSection())
	d.Sections = append(d.Sections, findingsSections(r.Findings)...)

	return d
}

func scoreSection(score model.ScoreBreakdown) Section {
	sec := Section{Heading: "Overall score", Level: 1}
	if !score.Applicable {
		sec.Paragraphs = []string{
			"No score is shown because every domain was skipped or failed - hostveil " +
				"could not look at enough of the host to score it, and a number here " +
				"would claim otherwise.",
		}
		return sec
	}

	sec.KV = append(sec.KV, KV{"Score", fmt.Sprintf("%d/100", score.Overall)})
	if after, ok := score.Headroom(); ok {
		sec.KV = append(sec.KV, KV{"After fixes", fmt.Sprintf("%d/100", after)})
	}
	sec.Paragraphs = []string{
		"hostveil scores each domain from 0 to 100 by how much of its own credit " +
			"survives the findings on it, then averages the domains that actually ran, " +
			"weighted by how much each matters to the whole host. A domain that could " +
			"not be scanned counts toward nothing, never toward a perfect score - see " +
			"\"Domains scanned\" below before reading this report as a verdict on the " +
			"whole host.",
	}
	if _, ok := score.Headroom(); ok {
		sec.Paragraphs = append(sec.Paragraphs,
			"\"After fixes\" is the score once every fix hostveil currently offers - "+
				"both the ones it can apply unattended and the ones it can only preview "+
				"- has been applied. It is shown only where it would actually move the "+
				"number.")
	}
	return sec
}

func domainsScoreSection(score model.ScoreBreakdown) Section {
	t := &Table{Headers: []string{"Domain", "Score", "Coverage", "After fixes"}}
	for _, ax := range score.Axes {
		coverage := "full"
		switch {
		case !ax.Applicable:
			coverage = "not run"
		case ax.Degraded:
			coverage = "partial"
		}
		after := ""
		if val, ok := ax.Headroom(); ok {
			after = fmt.Sprintf("%d", val)
		}
		t.Rows = append(t.Rows, []string{ax.Label, ax.ValueText(), coverage, after})
	}
	return Section{Heading: "Score by domain", Level: 1, Table: t}
}

func domainsScannedSection(domains []model.DomainResult) Section {
	t := &Table{Headers: []string{"Domain", "Result", "Detail"}}
	for _, dom := range domains {
		detail := dom.Reason
		if detail == "" {
			detail = "-"
		}
		t.Rows = append(t.Rows, []string{dom.Source.Label(), dom.State.String(), detail})
	}
	return Section{
		Heading: "Domains scanned",
		Level:   1,
		Paragraphs: []string{
			"Every domain hostveil knows how to check, and what happened when it ran. " +
				"This section exists because a score with no domain behind it is not a " +
				"perfect score: the absence of findings and the absence of a look are not " +
				"the same thing, and this report says which one happened for every row above.",
		},
		Table: t,
	}
}

func severityLegendSection() Section {
	sec := Section{
		Heading: "Severity - what the levels mean",
		Level:   1,
		Paragraphs: []string{
			"hostveil ranks findings by how urgent they are, not by how bad they sound.",
		},
	}
	for _, sev := range model.AllSeverities() {
		sec.KV = append(sec.KV, KV{Key: sev.String(), Value: sev.Description()})
	}
	return sec
}

// findingsSections groups active findings by severity, matching the order
// model.SortFindings already uses everywhere else in hostveil (severity,
// then source, then ID) rather than inventing a second order for the report.
func findingsSections(findings []model.Finding) []Section {
	var active []model.Finding
	for _, f := range findings {
		if f.Active() {
			active = append(active, f)
		}
	}
	model.SortFindings(active)

	header := Section{
		Heading: fmt.Sprintf("Findings (%d active)", len(active)),
		Level:   1,
	}
	if len(active) == 0 {
		header.Paragraphs = []string{"No active findings - every domain hostveil could scan came back clean."}
		return []Section{header}
	}

	sections := []Section{header}
	var current model.Severity
	var group []FindingBlock
	flush := func() {
		if len(group) == 0 {
			return
		}
		sections = append(sections, Section{
			Heading:  fmt.Sprintf("%s (%d)", capitalize(current.String()), len(group)),
			Level:    2,
			Findings: group,
		})
	}
	for i, f := range active {
		if i == 0 || f.Severity != current {
			flush()
			current = f.Severity
			group = nil
		}
		group = append(group, findingBlock(f))
	}
	flush()
	return sections
}

func findingBlock(f model.Finding) FindingBlock {
	fb := FindingBlock{
		Title:            f.Title,
		Severity:         f.Severity.String(),
		Domain:           f.Source.Label(),
		Service:          f.Service,
		Description:      f.Description,
		HowToFix:         f.HowToFix,
		WhyNoFix:         f.WhyNoFix,
		FixBenefit:       f.FixBenefit,
		FixSideEffect:    f.FixSideEffect,
		RemediationLabel: remediationContext(f.Remediation),
	}
	for k, v := range f.Evidence {
		fb.Evidence = append(fb.Evidence, KV{k, v})
	}
	sort.Slice(fb.Evidence, func(i, j int) bool { return fb.Evidence[i].Key < fb.Evidence[j].Key })
	return fb
}

// remediationContext pairs RemediationKind.Label() with one clause of
// context, so a reader who has never used hostveil understands what the
// classification means without cross-referencing anything else.
func remediationContext(k model.RemediationKind) string {
	switch k {
	case model.RemediationAuto:
		return k.Label() + " - hostveil can apply this unattended."
	case model.RemediationReview:
		return k.Label() + " - hostveil can preview a fix; you choose the alternative."
	case model.RemediationManual:
		return k.Label() + " - no automatable fix; see below."
	case model.RemediationUnavailable:
		return k.Label() + " - no fix exists yet."
	default:
		return k.Label()
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
