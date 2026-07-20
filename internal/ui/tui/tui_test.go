package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/seolcu/hostveil/internal/check"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// fakeRunner drives the compose checker without a real Docker daemon.
type fakeRunner struct {
	present map[string]bool
	lsJSON  string
}

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}
func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	switch {
	case name == "docker" && strings.Join(args, " ") == "compose ls --all --format json":
		return []byte(f.lsJSON), nil
	// Checkers probe the daemon before trusting the CLI's presence.
	case name == "docker" && strings.Join(args, " ") == "version --format {{.Server.Version}}":
		return []byte("27.0.3\n"), nil
	}
	return nil, errors.New("unexpected: " + name)
}

func sampleReport() model.Report {
	findings := []model.Finding{
		model.NewFinding("compose.ds018", "Datastore exposed", model.SeverityCritical,
			model.SourceCompose, model.RemediationAuto, model.WithService("cache"),
			model.WithDescription("A datastore is reachable from the internet."),
			model.WithHowToFix("Bind it to localhost.")),
		model.NewFinding("compose.ds001", "Privileged mode", model.SeverityHigh,
			model.SourceCompose, model.RemediationManual, model.WithService("app"),
			model.WithDescription("Privileged mode is dangerous.")),
	}
	return model.Report{
		Findings: findings,
		Score:    model.ScoreReport(findings, map[model.Source]model.ScanState{model.SourceCompose: model.ScanDone}),
	}
}

// key builds a KeyPressMsg for a single rune or named key.
func send(m tea.Model, msg tea.Msg) tea.Model {
	next, _ := m.Update(msg)
	return next
}

// TestSnapshotDump writes the rendered TUI frame to the path in
// HOSTVEIL_SNAPSHOT when set, for generating documentation screenshots. It
// is a no-op in normal test runs.
func TestSnapshotDump(t *testing.T) {
	path := os.Getenv("HOSTVEIL_SNAPSHOT")
	if path == "" {
		t.Skip("set HOSTVEIL_SNAPSHOT to dump a frame")
	}
	findings := []model.Finding{
		model.NewFinding("compose.ds018", "Datastore exposed on all network interfaces", model.SeverityCritical, model.SourceCompose, model.RemediationAuto, model.WithService("cache")),
		model.NewFinding("compose.ds016", "Docker socket mounted into container", model.SeverityCritical, model.SourceCompose, model.RemediationManual, model.WithService("portainer")),
		model.NewFinding("ssh.rootlogin", "SSH permits root login with a password", model.SeverityHigh, model.SourceSSH, model.RemediationReview),
		model.NewFinding("compose.ds019", "Admin panel exposed on all network interfaces", model.SeverityHigh, model.SourceCompose, model.RemediationManual, model.WithService("portainer")),
		model.NewFinding("compose.ds006", "Missing no-new-privileges hardening", model.SeverityMedium, model.SourceCompose, model.RemediationAuto, model.WithService("app")),
		model.NewFinding("updates.disabled", "Automatic security updates are not enabled", model.SeverityMedium, model.SourceUpdates, model.RemediationAuto),
		model.NewFinding("compose.ds008", "No restart policy set", model.SeverityLow, model.SourceCompose, model.RemediationAuto, model.WithService("db")),
	}
	states := map[model.Source]model.ScanState{model.SourceCompose: model.ScanDone, model.SourceSSH: model.ScanDone, model.SourceFirewall: model.ScanDone, model.SourceUpdates: model.ScanDone}
	rep := model.Report{Findings: findings, Score: model.ScoreReport(findings, states), Domains: []model.DomainResult{
		{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "Trivy not installed"},
	}}

	m := tea.Model(&appModel{mode: modeList})
	m = send(m, tea.WindowSizeMsg{Width: 96, Height: 34})
	m = send(m, scannedMsg{report: rep})
	if err := os.WriteFile(path, []byte(m.(*appModel).View().Content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestListScrolls verifies the list viewport follows the cursor when there
// are more findings than fit on screen.
func TestListScrolls(t *testing.T) {
	var fs []model.Finding
	for i := 0; i < 20; i++ {
		fs = append(fs, model.NewFinding(fmt.Sprintf("compose.d%03d", i),
			fmt.Sprintf("finding number %d", i), model.SeverityMedium,
			model.SourceCompose, model.RemediationManual))
	}
	rep := model.Report{Findings: fs, Score: model.ScoreReport(fs, nil)}

	m := tea.Model(&appModel{mode: modeList})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 12}) // only a few rows fit
	m = send(m, scannedMsg{report: rep})
	for i := 0; i < 19; i++ { // move to the last finding
		m = send(m, tea.KeyPressMsg(tea.Key{Text: "j"}))
	}

	view := m.(*appModel).View().Content
	if !strings.Contains(view, "compose.d019") {
		t.Error("the cursor's (last) finding should be visible after scrolling")
	}
	if strings.Contains(view, "compose.d000") {
		t.Error("the first finding should have scrolled out of view")
	}
}

func TestFilterNarrowsList(t *testing.T) {
	fs := []model.Finding{
		model.NewFinding("compose.ds018", "Datastore exposed", model.SeverityCritical, model.SourceCompose, model.RemediationAuto, model.WithService("cache")),
		model.NewFinding("compose.ds001", "Privileged", model.SeverityHigh, model.SourceCompose, model.RemediationManual, model.WithService("app")),
		model.NewFinding("updates.disabled", "Auto-updates off", model.SeverityMedium, model.SourceUpdates, model.RemediationReview),
	}
	rep := model.Report{Findings: fs, Score: model.ScoreReport(fs, nil)}

	m := tea.Model(&appModel{mode: modeList, selected: map[string]bool{}})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: rep})
	if got := len(m.(*appModel).active); got != 3 {
		t.Fatalf("want 3 active, got %d", got)
	}

	// s once → minimum severity Critical → only the crit finding.
	m = send(m, tea.KeyPressMsg(tea.Key{Text: "s"}))
	if got := len(m.(*appModel).active); got != 1 {
		t.Errorf("severity filter: want 1, got %d", got)
	}
	// c → clear.
	m = send(m, tea.KeyPressMsg(tea.Key{Text: "c"}))
	if got := len(m.(*appModel).active); got != 3 {
		t.Errorf("clear: want 3, got %d", got)
	}
	// d once → first present domain (compose) → 2 compose findings.
	m = send(m, tea.KeyPressMsg(tea.Key{Text: "d"}))
	if got := len(m.(*appModel).active); got != 2 {
		t.Errorf("domain filter: want 2 compose, got %d", got)
	}
	// x → fixable-only, on top of compose → only the Auto ds018.
	m = send(m, tea.KeyPressMsg(tea.Key{Text: "x"}))
	am := m.(*appModel)
	if len(am.active) != 1 || am.active[0].ID != "compose.ds018" {
		t.Errorf("fixable filter: want [compose.ds018], got %d findings", len(am.active))
	}
}

// TestMultiSelectBatchApply marks two auto-fixable findings and applies them
// as a batch through a real engine, confirming both files are edited.
func TestMultiSelectBatchApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	yaml := "services:\n" +
		"  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n" +
		"  store:\n    image: redis\n    ports:\n      - \"6380:6380\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := core.New(core.Config{
		Registry: check.NewRegistry(composecheck.New()),
		Fixes:    fix.Default(),
		Store:    history.NewStore(t.TempDir()),
		Runner:   fakeRunner{present: map[string]bool{"docker": true}, lsJSON: `[{"Name":"demo","ConfigFiles":"` + path + `"}]`},
	})
	rep := engine.Scan(context.Background(), nil)

	m := tea.Model(&appModel{engine: engine, mode: modeList, selected: map[string]bool{}})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: rep})

	// Mark every auto-fixable exposed-datastore finding.
	am := m.(*appModel)
	marked := 0
	for _, f := range am.active {
		if f.ID == "compose.ds018" && f.Remediation == model.RemediationAuto {
			am.selected[f.Key()] = true
			marked++
		}
	}
	if marked != 2 {
		t.Fatalf("expected 2 exposed datastores to mark, got %d", marked)
	}

	// a → batch command; run it and feed the result back.
	_, cmd := m.Update(tea.KeyPressMsg(tea.Key{Text: "a"}))
	if cmd == nil {
		t.Fatal("a should issue a batch command")
	}
	m = send(m, cmd())
	am = m.(*appModel)
	if !strings.Contains(am.status, "Applied 2") {
		t.Errorf("expected 'Applied 2' status, got %q", am.status)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "127.0.0.1:6379:6379") || !strings.Contains(string(data), "127.0.0.1:6380:6380") {
		t.Errorf("both datastores should be bound to loopback:\n%s", data)
	}
	for _, f := range am.active {
		if f.ID == "compose.ds018" {
			t.Error("fixed datastores should be gone from the refreshed list")
		}
	}
	if len(am.selected) != 0 {
		t.Error("selection should be cleared after a batch apply")
	}
}

// TestSpaceTogglesOnlyAuto verifies space marks auto rows and ignores others.
func TestSpaceTogglesOnlyAuto(t *testing.T) {
	m := tea.Model(&appModel{mode: modeList, selected: map[string]bool{}})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: sampleReport()}) // ds018 Auto (cursor 0), ds001 Manual

	m = send(m, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace})) // mark the Auto finding
	if got := len(m.(*appModel).selected); got != 1 {
		t.Fatalf("space on auto row: want 1 marked, got %d", got)
	}
	m = send(m, tea.KeyPressMsg(tea.Key{Text: "j"}))          // to the Manual finding
	m = send(m, tea.KeyPressMsg(tea.Key{Code: tea.KeySpace})) // should be a no-op
	if got := len(m.(*appModel).selected); got != 1 {
		t.Errorf("space on manual row must not mark: want 1, got %d", got)
	}
}

func TestListRenders(t *testing.T) {
	m := &appModel{engine: nil, mode: modeList}
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40}).(*appModel)
	m = send(m, scannedMsg{report: sampleReport()}).(*appModel)

	view := m.View().Content
	if !strings.Contains(view, "compose.ds018") || !strings.Contains(view, "compose.ds001") {
		t.Errorf("list view missing findings:\n%s", view)
	}
	if !strings.Contains(view, "SECURITY") {
		t.Error("list view missing score header")
	}
}

func TestNavigationAndDetail(t *testing.T) {
	m := tea.Model(&appModel{mode: modeList})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: sampleReport()})

	// Move down to the second finding, open detail.
	m = send(m, tea.KeyPressMsg(tea.Key{Text: "j"}))
	m = send(m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))

	am := m.(*appModel)
	if am.mode != modeDetail {
		t.Fatalf("expected detail mode, got %v", am.mode)
	}
	view := am.View().Content
	if !strings.Contains(view, "Privileged mode is dangerous") {
		t.Errorf("detail view missing description:\n%s", view)
	}

	// Esc returns to the list.
	m = send(m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape}))
	if m.(*appModel).mode != modeList {
		t.Error("esc should return to list mode")
	}
}

func TestManualFindingCannotBeFixed(t *testing.T) {
	m := tea.Model(&appModel{mode: modeList})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: sampleReport()})
	// Cursor on ds018 (fixable) → move to ds001 (manual).
	m = send(m, tea.KeyPressMsg(tea.Key{Text: "j"}))
	m = send(m, tea.KeyPressMsg(tea.Key{Text: "f"}))
	am := m.(*appModel)
	if am.mode != modeMessage || !strings.Contains(am.status, "Manual") {
		t.Errorf("fixing a manual finding should show a message, got mode=%v status=%q", am.mode, am.status)
	}
}

// TestFixFlowThroughEngine drives preview→apply against a real engine and
// fixture file, confirming the TUI's thin path reaches the engine.
func TestFixFlowThroughEngine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A real engine + fake runner, so engine.Scan populates the authoritative
	// current report the TUI refreshes from after a fix.
	engine := core.New(core.Config{
		Registry: check.NewRegistry(composecheck.New()),
		Fixes:    fix.Default(),
		Store:    history.NewStore(t.TempDir()),
		Runner:   fakeRunner{present: map[string]bool{"docker": true}, lsJSON: `[{"Name":"demo","ConfigFiles":"` + path + `"}]`},
	})
	rep := engine.Scan(context.Background(), nil)

	m := tea.Model(&appModel{engine: engine, mode: modeList})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: rep})
	// Put the cursor on the exposed-datastore finding.
	for i, f := range m.(*appModel).active {
		if f.ID == "compose.ds018" {
			m.(*appModel).cursor = i
		}
	}

	// Preview then apply, executing the returned commands synchronously.
	_, cmd := m.Update(tea.KeyPressMsg(tea.Key{Text: "f"}))
	if cmd == nil {
		t.Fatal("f should issue a preview command")
	}
	m = send(m, cmd()) // previewMsg
	if m.(*appModel).mode != modePreview {
		t.Fatalf("expected preview mode, got %v", m.(*appModel).mode)
	}
	_, cmd = m.Update(tea.KeyPressMsg(tea.Key{Text: "y"}))
	if cmd == nil {
		t.Fatal("y should issue an apply command")
	}
	m = send(m, cmd()) // appliedMsg

	am := m.(*appModel)
	if !strings.Contains(am.status, "Fix applied") {
		t.Errorf("expected applied status, got %q", am.status)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "127.0.0.1:6379:6379") {
		t.Errorf("fix not applied to file:\n%s", data)
	}
	// The engine marked ds018 fixed, so the refreshed active list no longer
	// contains it.
	for _, f := range am.active {
		if f.ID == "compose.ds018" {
			t.Error("fixed finding should be gone from the refreshed active list")
		}
	}
}

// TestRollbackFlowThroughEngine is the TUI half of "reversible anywhere":
// apply a fix, open the history screen with h, roll it back, and confirm
// the file is restored and the finding is back in the active list.
func TestRollbackFlowThroughEngine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	orig := "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := core.New(core.Config{
		Registry: check.NewRegistry(composecheck.New()),
		Fixes:    fix.Default(),
		Store:    history.NewStore(t.TempDir()),
		Runner:   fakeRunner{present: map[string]bool{"docker": true}, lsJSON: `[{"Name":"demo","ConfigFiles":"` + path + `"}]`},
	})
	rep := engine.Scan(context.Background(), nil)

	m := tea.Model(&appModel{engine: engine, mode: modeList, selected: map[string]bool{}})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: rep})
	for i, f := range m.(*appModel).active {
		if f.ID == "compose.ds018" {
			m.(*appModel).cursor = i
		}
	}

	// Apply the fix.
	_, cmd := m.Update(tea.KeyPressMsg(tea.Key{Text: "f"}))
	m = send(m, cmd())
	_, cmd = m.Update(tea.KeyPressMsg(tea.Key{Text: "y"}))
	m = send(m, cmd())
	if data, _ := os.ReadFile(path); string(data) == orig {
		t.Fatal("fix was not applied")
	}
	// The message should point at the history screen, not a bare ID the user
	// can only act on by quitting to the CLI.
	if !strings.Contains(m.(*appModel).status, "h to undo") {
		t.Errorf("apply status should point at the history screen, got %q", m.(*appModel).status)
	}

	// Dismiss the message, then open history with h.
	m = send(m, tea.KeyPressMsg(tea.Key{Text: " "}))
	_, cmd = m.Update(tea.KeyPressMsg(tea.Key{Text: "h"}))
	if cmd == nil {
		t.Fatal("h should issue a history command")
	}
	m = send(m, cmd())
	hm := m.(*appModel)
	if hm.mode != modeHistory {
		t.Fatalf("expected history mode, got %v", hm.mode)
	}
	if len(hm.checkpoints) != 1 {
		t.Fatalf("want 1 checkpoint, got %d", len(hm.checkpoints))
	}
	if view := m.(*appModel).viewHistory(); !strings.Contains(view, "compose.ds018") {
		t.Errorf("history view should name the finding:\n%s", view)
	}

	// enter → confirm screen → y rolls back.
	m = send(m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if m.(*appModel).mode != modeRollbackConfirm {
		t.Fatalf("enter on a reversible checkpoint should ask to confirm, got %v", m.(*appModel).mode)
	}
	_, cmd = m.Update(tea.KeyPressMsg(tea.Key{Text: "y"}))
	if cmd == nil {
		t.Fatal("y should issue a rollback command")
	}
	m = send(m, cmd())

	am := m.(*appModel)
	if !strings.Contains(am.status, "Rolled back") {
		t.Errorf("expected rollback status, got %q", am.status)
	}
	if data, _ := os.ReadFile(path); string(data) != orig {
		t.Errorf("rollback did not restore the original bytes:\nwant:\n%s\ngot:\n%s", orig, data)
	}
	// The whole point: the finding is back, so the TUI stops claiming a fix
	// that has been undone.
	var back bool
	for _, f := range am.active {
		if f.ID == "compose.ds018" {
			back = true
		}
	}
	if !back {
		t.Error("rolled-back finding should be in the active list again")
	}
}

// TestHistoryWithNoCheckpoints keeps h from opening an empty screen.
func TestHistoryWithNoCheckpoints(t *testing.T) {
	engine := core.New(core.Config{Fixes: fix.Default(), Store: history.NewStore(t.TempDir())})
	m := tea.Model(&appModel{engine: engine, mode: modeList, selected: map[string]bool{}})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m = send(m, scannedMsg{report: sampleReport()})

	_, cmd := m.Update(tea.KeyPressMsg(tea.Key{Text: "h"}))
	if cmd == nil {
		t.Fatal("h should issue a history command")
	}
	m = send(m, cmd())
	am := m.(*appModel)
	if am.mode != modeMessage {
		t.Errorf("empty history should show a message, got mode %v", am.mode)
	}
	if !strings.Contains(am.status, "No fixes") {
		t.Errorf("unexpected status: %q", am.status)
	}
}

// TestNonReversibleCheckpointOffersNoRollback: exec fixes back up no files,
// so the TUI must explain that rather than appearing to roll one back.
func TestNonReversibleCheckpointOffersNoRollback(t *testing.T) {
	m := &appModel{
		mode:   modeHistory,
		width:  100,
		height: 40,
		checkpoints: []model.Checkpoint{{
			ID: "cp1", FindingID: "updates.disabled", Label: "Enable unattended upgrades",
			Reversible: false, Commands: [][]string{{"systemctl", "enable", "unattended-upgrades"}},
		}},
	}
	next, _ := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	am := next.(*appModel)
	if am.mode != modeMessage {
		t.Errorf("expected an explanatory message, got mode %v", am.mode)
	}
	if !strings.Contains(am.status, "nothing to restore") {
		t.Errorf("unexpected status: %q", am.status)
	}
}

// TestDeltaLineRendersOnlyWhenSomethingMoved: the engine computes a delta
// on every scan, but a first scan has nothing to compare against, and a
// scan that changed nothing should not add a line saying so.
func TestDeltaLineRendersOnlyWhenSomethingMoved(t *testing.T) {
	m := &appModel{engine: nil, mode: modeList}
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40}).(*appModel)

	m = send(m, scannedMsg{report: sampleReport()}).(*appModel)
	if strings.Contains(m.View().Content, "since last scan") {
		t.Error("a scan with no delta should not render a since-last-scan line")
	}

	prev := sampleReport().Findings[0]
	m = send(m, scannedMsg{
		report: sampleReport(),
		delta:  model.Delta{Resolved: []model.Finding{prev}, StillPresent: 2},
	}).(*appModel)
	view := m.View().Content
	if !strings.Contains(view, "since last scan") || !strings.Contains(view, "1 resolved") {
		t.Errorf("expected a since-last-scan summary naming 1 resolved:\n%s", view)
	}
}
