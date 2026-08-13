// Package uitest holds the one host the website's screenshots are pictures of.
//
// Both published screenshots draw a scan result, and until this existed they
// drew two different ones: the terminal frame came from a fixture in the TUI's
// tests and the dashboard from whatever host somebody happened to point a
// browser at. A reader looking at the two pictures on one page has no way to
// know they are not the same machine, and there was no reason for them not to
// be — only that nothing described the host in a place both could read.
//
// It is exported for the same reason internal/check/checktest and
// internal/fix/fixtest are: the answer is needed outside the package that
// knows it, and a copy in each caller is a copy that drifts.
package uitest

import "github.com/seolcu/hostveil/internal/model"

// PublishedReport is the scan the website's screenshots show.
//
// It is deliberately a mixed host rather than a wrecked one. Every claim the
// pages make beside these pictures has to be visible in them: three severity
// levels, a domain that ran but covered only part of its ground, a domain that
// did not run at all and reads N/A instead of a free 100, findings at every
// remediation kind, and enough fixable ones that the headroom figure has
// something to say. A host with eighty findings looks alarming and shows none
// of that.
func PublishedReport() model.Report {
	findings := []model.Finding{
		model.NewFinding("compose.ds018", "Datastore exposed on all network interfaces", model.SeverityHigh, model.SourceCompose, model.RemediationAuto, model.WithService("cloud/redis"),
			model.WithDescription("The redis container publishes port 6379 on 0.0.0.0, so anything that can reach this host can reach the datastore. Redis has no authentication enabled by default, which means a full read and write of everything the service keeps there."),
			model.WithHowToFix("Bind the published port to 127.0.0.1 so only this host can connect, and reach it from other containers over the compose network instead.")),
		model.NewFinding("compose.ds016", "Docker socket mounted into container", model.SeverityHigh, model.SourceCompose, model.RemediationManual, model.WithService("ops/portainer"),
			model.WithDescription("Mounting /var/run/docker.sock gives the container full control of the Docker daemon, which is equivalent to root on the host.")),
		model.NewFinding("cve.outdated-image", "12 fixable vulnerabilities in nextcloud:27.1.3", model.SeverityHigh, model.SourceCVE, model.RemediationReview, model.WithService("cloud/nextcloud")),
		model.NewFinding("ssh.rootlogin", "SSH permits root login with a password", model.SeverityHigh, model.SourceSSH, model.RemediationReview,
			model.WithDescription("PermitRootLogin is set to yes, so anyone who guesses the root password is root on this host."),
			model.WithHowToFix("Set PermitRootLogin prohibit-password after confirming you have a working key-based login for a non-root user.")),
		model.NewFinding("compose.ds019", "Admin panel exposed on all network interfaces", model.SeverityHigh, model.SourceCompose, model.RemediationManual, model.WithService("ops/portainer")),
		model.NewFinding("compose.ds006", "Missing no-new-privileges hardening", model.SeverityMedium, model.SourceCompose, model.RemediationAuto, model.WithService("cloud/nextcloud")),
		model.NewFinding("updates.disabled", "Automatic security updates are not enabled", model.SeverityMedium, model.SourceUpdates, model.RemediationAuto),
		model.NewFinding("firewall.inactive", "ufw is installed but not enabled", model.SeverityMedium, model.SourceFirewall, model.RemediationReview),
		model.NewFinding("fileperms.envfile", "An .env file is world-readable", model.SeverityMedium, model.SourceFilePerms, model.RemediationAuto, model.WithService("cloud")),
		model.NewFinding("sysctl.kptr-restrict", "Kernel pointers are readable by unprivileged users", model.SeverityLow, model.SourceSysctl, model.RemediationReview),
		model.NewFinding("compose.ds008", "No restart policy set", model.SeverityLow, model.SourceCompose, model.RemediationAuto, model.WithService("cloud/collabora")),
		model.NewFinding("compose.ds010", "No memory limit set", model.SeverityLow, model.SourceCompose, model.RemediationAuto, model.WithService("media/jellyfin")),
		model.NewFinding("ssh.maxauth", "MaxAuthTries is higher than necessary", model.SeverityLow, model.SourceSSH, model.RemediationAuto),
	}
	// Built from AllSources rather than listed, because a hand-written table
	// keyed by Source is a copy waiting to go stale — and this one already
	// had. SourceDockerd appeared in neither the states nor the domains, so
	// the axis read as zero-value ScanPending: N/A with no DomainResult
	// beside it and therefore no reason. "I could not look, and I will not
	// say why" is the exact state the rail exists to prevent, and it was in
	// both pictures published on the website.
	//
	// Only the exceptions are spelled out now. A thirteenth domain lands as
	// ScanDone and shows up in the screenshots rather than vanishing from
	// them.
	//
	// The exceptions also have to describe a host that could exist. Dockerd
	// was briefly marked unreachable here, which cannot be true of a host
	// whose CVE domain scored image vulnerabilities — Trivy reaches those
	// images through the daemon. A fixture that contradicts itself teaches a
	// reader the wrong thing about which domain depends on what.
	exceptions := map[model.Source]model.DomainResult{
		model.SourceAgent: {State: model.ScanSkipped, Reason: "no self-hosted agent runtime found"},
		model.SourcePorts: {State: model.ScanDegraded, Reason: "ss reported no process names — run as root to attribute listeners"},
	}

	states := map[model.Source]model.ScanState{}
	var domains []model.DomainResult
	for _, src := range model.AllSources() {
		st := model.ScanDone
		if ex, ok := exceptions[src]; ok {
			st = ex.State
			ex.Source = src
			domains = append(domains, ex)
		}
		states[src] = st
	}

	return model.Report{
		Findings: findings,
		Score:    model.ScoreReport(findings, states),
		Domains:  domains,
	}
}
