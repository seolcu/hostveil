package tui

import (
	"context"
	"errors"
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
	if name == "docker" && strings.Join(args, " ") == "compose ls --all --format json" {
		return []byte(f.lsJSON), nil
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
		Score:    model.ScoreReport(findings, map[model.Source]bool{model.SourceCompose: true}),
	}
}

// key builds a KeyPressMsg for a single rune or named key.
func send(m tea.Model, msg tea.Msg) tea.Model {
	next, _ := m.Update(msg)
	return next
}

func TestListRenders(t *testing.T) {
	m := &appModel{engine: nil, mode: modeList}
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40}).(*appModel)
	m = send(m, scannedMsg{report: sampleReport()}).(*appModel)

	view := m.View().Content
	if !strings.Contains(view, "compose.ds018") || !strings.Contains(view, "compose.ds001") {
		t.Errorf("list view missing findings:\n%s", view)
	}
	if !strings.Contains(view, "Security score") {
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
