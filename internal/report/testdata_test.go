package report

import "github.com/seolcu/hostveil/internal/model"

// sampleReport builds a small but representative report: one High finding
// with a Review remediation and evidence, one Medium finding with no fix
// (WhyNoFix set), one fixed finding (must not appear in the export), and
// one domain that was skipped — so every format's tests can check that a
// partial scan is visibly called out rather than silently scoring 100.
func sampleReport() model.Report {
	high := model.NewFinding("ssh.rootlogin", "SSH permits root login with a password",
		model.SeverityHigh, model.SourceSSH, model.RemediationReview,
		model.WithDescription("An attacker who guesses or steals the root password can log in directly."),
		model.WithHowToFix("Set PermitRootLogin to no or prohibit-password in sshd_config."),
		model.WithEvidence("PermitRootLogin", "yes"))
	// Set directly rather than through Engine.classify, which this package
	// cannot reach without importing internal/core — the same reason the
	// export renderers themselves never build a Fix.
	high.FixBenefit = "Keeps key-based root access working while removing the one thing root " +
		"logins are actually dangerous for: a guessable or stolen password."
	high.FixSideEffect = "Keep a working key for root, or use a sudo user instead."

	medium := model.NewFinding("agent.dockersock", "Container has the Docker socket mounted",
		model.SeverityMedium, model.SourceAgent, model.RemediationManual,
		model.WithDescription("A container with the Docker socket can control every other container on the host."),
		model.WithService("portainer"))
	medium.WhyNoFix = "Removing the mount would break the container's intended function; hostveil cannot judge that trade-off."

	fixed := model.NewFinding("ssh.x11forwarding", "X11 forwarding is enabled",
		model.SeverityLow, model.SourceSSH, model.RemediationAuto)
	fixed.Fixed = true

	findings := []model.Finding{high, medium, fixed}
	states := map[model.Source]model.ScanState{
		model.SourceSSH:   model.ScanDone,
		model.SourceAgent: model.ScanDone,
		model.SourceCVE:   model.ScanSkipped,
	}
	score := model.ScoreReport(findings, states)

	domains := []model.DomainResult{
		{Source: model.SourceSSH, State: model.ScanDone, FindingCount: 1},
		{Source: model.SourceAgent, State: model.ScanDone, FindingCount: 1},
		{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "trivy is not installed"},
	}

	return model.Report{Findings: findings, Score: score, Domains: domains}
}
