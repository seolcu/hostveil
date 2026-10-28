package tui

import (
	"fmt"

	"github.com/seolcu/hostveil/internal/model"
)

// layoutFixture is a host with every severity present, some findings
// Hostveil can fix on its own, a skipped domain and a degraded one. The rail
// and the verdict are both summaries, and a fixture missing any of those
// would let a summary pass by having nothing to summarise.
func layoutFixture() model.Report {
	var fs []model.Finding
	add := func(n int, id string, sev model.Severity, rem model.RemediationKind, src model.Source) {
		for i := range n {
			fs = append(fs, model.NewFinding(id, "Datastore exposed on all network interfaces",
				sev, src, rem, model.WithService(fmt.Sprintf("svc-%d", i)),
				model.WithDescription("A database or cache published on 0.0.0.0 is reachable from the internet."),
				model.WithHowToFix("Bind the port to 127.0.0.1 and set a strong password.")))
		}
	}
	add(3, "compose.ds018", model.SeverityHigh, model.RemediationAuto, model.SourceCompose)
	add(5, "compose.ds016", model.SeverityMedium, model.RemediationManual, model.SourceCompose)
	add(7, "ssh.rootlogin", model.SeverityMedium, model.RemediationAuto, model.SourceSSH)
	add(11, "ports.exposed", model.SeverityLow, model.RemediationManual, model.SourcePorts)

	// Firewall is degraded and carries no findings, so it scores 100 and its
	// value text is "100~" — the widest an axis value can be, and one column
	// more than every renderer used to budget for it. The fixture had a
	// degraded domain already, but a degraded domain *with* findings scores
	// below 100 and fits, which is why every width sweep in this package
	// passed over the overflow for as long as it existed.
	states := map[model.Source]model.ScanState{
		model.SourceCompose:  model.ScanDone,
		model.SourceSSH:      model.ScanDone,
		model.SourcePorts:    model.ScanDegraded,
		model.SourceFirewall: model.ScanDegraded,
		model.SourceCVE:      model.ScanSkipped,
	}
	return model.Report{
		Findings: fs,
		Score:    model.ScoreReport(fs, states),
		Domains: []model.DomainResult{
			{Source: model.SourceCompose, State: model.ScanDone, FindingCount: 8},
			{Source: model.SourceSSH, State: model.ScanDone, FindingCount: 7},
			{Source: model.SourcePorts, State: model.ScanDegraded, Reason: "the firewall would not answer"},
			{Source: model.SourceFirewall, State: model.ScanDegraded, Reason: "cannot read the DOCKER-USER chain"},
			{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy is not installed"},
		},
	}
}

// layoutModel is the findings screen over layoutFixture at w×h.
func layoutModel(w, h int) *appModel {
	m := &appModel{mode: modeList, width: w, height: h,
		report: layoutFixture(), selected: map[string]bool{}}
	m.active = m.report.Select(m.filter)
	return m
}
