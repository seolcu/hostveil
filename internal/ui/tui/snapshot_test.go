package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

// The palette and arrangement the dump renders in. Both default to what a
// first run shows, so the committed frames do not move; both are named because
// a palette change and an arrangement change are exactly the two things a
// screenshot is the only honest review of, and neither is visible in the one
// arrangement the dumper used to be hardwired to.
//
// An unknown ID is a hard failure rather than a silent fall back to the
// default: a typo would otherwise produce a full set of frames that look
// right, are named after the theme asked for, and are drawn in another one.
const (
	snapshotThemeEnv  = "HOSTVEIL_SNAPSHOT_THEME"
	snapshotLayoutEnv = "HOSTVEIL_SNAPSHOT_LAYOUT"
)

func snapshotTheme(t *testing.T) theme.Theme {
	t.Helper()
	id := os.Getenv(snapshotThemeEnv)
	if id == "" {
		return theme.Default()
	}
	th, ok := theme.Lookup(id)
	if !ok {
		t.Fatalf("%s=%q is not a theme; have %s", snapshotThemeEnv, id, strings.Join(theme.IDs(), ", "))
	}
	return th
}

func snapshotLayout(t *testing.T) string {
	t.Helper()
	id := os.Getenv(snapshotLayoutEnv)
	if id == "" {
		return ""
	}
	if _, ok := LookupLayout(id); !ok {
		t.Fatalf("%s=%q is not an arrangement; have %s", snapshotLayoutEnv, id, strings.Join(LayoutIDs(), ", "))
	}
	return id
}

// dumpEveryMode writes one .ans per screen into dir, in the order a user
// meets them. Reached from TestSnapshotDump when HOSTVEIL_SNAPSHOT names a
// directory; see that test for why there is only the one hook.
//
// The fixture is deliberately a plausible host rather than a minimal one: a
// full nine domains, one of them degraded, findings at every severity, a
// couple marked, and enough of them to scroll. A layout only misbehaves when
// there is something in it.
func dumpEveryMode(t *testing.T, dir string) {
	t.Helper()
	const W, H = 100, 34

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
		model.NewFinding("ports.database", "PostgreSQL is listening on a public interface", model.SeverityHigh, model.SourcePorts, model.RemediationManual, model.WithService("postgres")),
		model.NewFinding("compose.ds019", "Admin panel exposed on all network interfaces", model.SeverityHigh, model.SourceCompose, model.RemediationManual, model.WithService("ops/portainer")),
		model.NewFinding("accounts.nopasswd", "A sudoers rule grants NOPASSWD to a human account", model.SeverityHigh, model.SourceAccounts, model.RemediationManual, model.WithService("deploy")),
		model.NewFinding("compose.ds006", "Missing no-new-privileges hardening", model.SeverityMedium, model.SourceCompose, model.RemediationAuto, model.WithService("cloud/nextcloud")),
		model.NewFinding("updates.disabled", "Automatic security updates are not enabled", model.SeverityMedium, model.SourceUpdates, model.RemediationAuto),
		model.NewFinding("firewall.inactive", "ufw is installed but not enabled", model.SeverityMedium, model.SourceFirewall, model.RemediationReview),
		model.NewFinding("fileperms.envfile", "An .env file is world-readable", model.SeverityMedium, model.SourceFilePerms, model.RemediationAuto, model.WithService("cloud")),
		model.NewFinding("agent.toolsopen", "An AI agent config allows unattended shell access", model.SeverityMedium, model.SourceAgent, model.RemediationManual, model.WithService("opencode")),
		model.NewFinding("compose.ds008", "No restart policy set", model.SeverityLow, model.SourceCompose, model.RemediationAuto, model.WithService("cloud/collabora")),
		model.NewFinding("compose.ds002", "Container runs as root", model.SeverityLow, model.SourceCompose, model.RemediationReview, model.WithService("ops/watchtower")),
		model.NewFinding("ssh.maxauth", "MaxAuthTries is higher than necessary", model.SeverityLow, model.SourceSSH, model.RemediationAuto),
	}
	states := map[model.Source]model.ScanState{
		model.SourceCompose: model.ScanDone, model.SourceSSH: model.ScanDone,
		model.SourceFirewall: model.ScanDone, model.SourceUpdates: model.ScanDone,
		model.SourcePorts: model.ScanDegraded, model.SourceAccounts: model.ScanDone,
		model.SourceFilePerms: model.ScanDone, model.SourceAgent: model.ScanDone,
		model.SourceCVE: model.ScanDone,
	}
	rep := model.Report{Findings: findings, Score: model.ScoreReport(findings, states)}
	delta := model.Delta{Resolved: findings[:2], New: findings[2:3], StillPresent: 12}

	pal, lay := snapshotTheme(t), snapshotLayout(t)
	newModel := func(md mode) *appModel {
		m := &appModel{mode: md, width: W, height: H, report: rep, delta: delta,
			selected: map[string]bool{}, status: "Scanning…", layout: lay}
		m.setTheme(pal)
		m.rebuildActive()
		return m
	}
	dump := func(name string, m *appModel) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name+".ans"), []byte(m.View().Content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dump("01-scanning", newModel(modeScanning))

	list := newModel(modeList)
	list.cursor = 3
	for _, f := range list.active {
		if f.Remediation == model.RemediationAuto && len(list.selected) < 3 {
			list.selected[f.Key()] = true
		}
	}
	dump("02-list", list)

	filtered := newModel(modeList)
	sev := model.SeverityHigh
	filtered.filter = model.Filter{MinSeverity: &sev, FixableOnly: true}
	filtered.rebuildActive()
	filtered.cursor = 1
	dump("03-list-filtered", filtered)

	dump("04-detail", newModel(modeDetail))

	pv := newModel(modePreview)
	pv.preview = model.FixPreview{
		FindingID: "compose.ds018", Label: "Bind redis to loopback", Kind: model.RemediationAuto,
		Actions: []model.ActionPreview{{Index: 0, Label: "Publish on 127.0.0.1 only", Type: "edit",
			Path: "/opt/stacks/cloud/docker-compose.yml",
			Diff: "--- /opt/stacks/cloud/docker-compose.yml\n" +
				"+++ /opt/stacks/cloud/docker-compose.yml\n" +
				"@@ -14,7 +14,7 @@\n" +
				"   redis:\n     image: redis:7-alpine\n     ports:\n" +
				"-      - \"6379:6379\"\n+      - \"127.0.0.1:6379:6379\"\n" +
				"     restart: unless-stopped\n"}},
	}
	dump("05-preview-edit", pv)

	pv2 := newModel(modePreview)
	pv2.preview = model.FixPreview{
		FindingID: "cve.outdated-image", Label: "Update the image for nextcloud", Kind: model.RemediationReview,
		Actions: []model.ActionPreview{
			{Index: 0, Label: "Pull the new image and recreate nextcloud now", Type: "exec",
				Warning: "This recreates the container: the service goes down briefly and comes back on a different image. There is no rollback checkpoint — exec fixes are not file-backed, so hostveil cannot undo this.",
				Commands: [][]string{
					{"docker", "compose", "-f", "/opt/stacks/cloud/docker-compose.yml", "pull", "nextcloud"},
					{"docker", "compose", "-f", "/opt/stacks/cloud/docker-compose.yml", "up", "-d", "nextcloud"}}},
			{Index: 1, Label: "Download the image only, recreate it yourself later", Type: "exec",
				Commands: [][]string{{"docker", "compose", "-f", "/opt/stacks/cloud/docker-compose.yml", "pull", "nextcloud"}}},
		},
	}
	dump("06-preview-exec", pv2)

	msg := newModel(modeMessage)
	msg.status = "✓ Fix applied. Press h to undo it. New score: 61/100. You may need to restart 'redis'."
	dump("07-message", msg)

	// A fixed date: the history rows show a timestamp, and time.Now() would
	// make every dump differ from the last for no reason anyone cares about.
	base := time.Date(2026, 7, 26, 14, 3, 0, 0, time.Local)
	cps := []model.Checkpoint{
		{ID: "cp7", FindingID: "compose.ds018", Label: "Bind redis to loopback", CreatedAt: base, Reversible: true,
			Files: []string{"/opt/stacks/cloud/docker-compose.yml"}, RestartService: "redis",
			Diff: "--- /opt/stacks/cloud/docker-compose.yml\n+++ /opt/stacks/cloud/docker-compose.yml\n@@ -14,7 +14,7 @@\n   redis:\n     image: redis:7-alpine\n     ports:\n-      - \"6379:6379\"\n+      - \"127.0.0.1:6379:6379\"\n     restart: unless-stopped\n"},
		{ID: "cp6", FindingID: "compose.ds006", Label: "Add no-new-privileges to nextcloud", CreatedAt: base.Add(-42 * time.Minute), Reversible: true},
		{ID: "cp5", FindingID: "updates.disabled", Label: "Enable unattended-upgrades", CreatedAt: base.Add(-3 * time.Hour), Reversible: true},
		{ID: "cp4", FindingID: "firewall.inactive", Label: "Enable ufw with the current ports allowed", CreatedAt: base.Add(-26 * time.Hour), Reversible: false},
		{ID: "cp3", FindingID: "fileperms.envfile", Label: "Restrict /opt/stacks/cloud/.env to the owner", CreatedAt: base.Add(-50 * time.Hour), Reversible: true},
		{ID: "cp2", FindingID: "ssh.maxauth", Label: "Set MaxAuthTries to 3", CreatedAt: base.Add(-74 * time.Hour), Reversible: true},
	}

	hist := newModel(modeHistory)
	hist.checkpoints = cps
	dump("08-history", hist)

	rb := newModel(modeRollbackConfirm)
	rb.checkpoints = cps
	dump("09-rollback", rb)

	th := newModel(modeTheme)
	th.openThemePicker()
	th.mode = modeTheme
	dump("10-theme", th)

	clean := &appModel{mode: modeList, width: W, height: H, selected: map[string]bool{},
		report: model.Report{Score: model.ScoreReport(nil, states)}, layout: lay}
	clean.setTheme(pal)
	clean.rebuildActive()
	dump("11-clean", clean)

	// The size every layout regression shows up at first.
	narrow := newModel(modeList)
	narrow.width, narrow.height = 80, 24
	narrow.cursor = 2
	dump("12-narrow", narrow)
}
