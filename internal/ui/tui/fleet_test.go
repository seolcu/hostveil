package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

func fleetFixture() model.Fleet {
	high := model.NewFinding("ssh.rootlogin", "SSH permits root login", model.SeverityHigh, model.SourceSSH, model.RemediationReview)
	return model.Fleet{Hosts: []model.FleetEntry{
		{Host: "web1", Report: &model.Report{Score: model.ScoreBreakdown{Overall: 92, Applicable: true}}},
		{Host: "db1", Report: &model.Report{Findings: []model.Finding{high}, Score: model.ScoreBreakdown{Overall: 41, Applicable: true}}},
		{Host: "nas", Error: "could not connect over SSH: Connection refused"},
	}}
}

func loadedFleet(t *testing.T) *fleetModel {
	t.Helper()
	m := newFleetModel(nil, nil, []string{"web1", "db1", "nas"}, FleetOpts{Theme: theme.Default()})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.Update(fleetDoneMsg(fleetFixture()))
	return m
}

// A host nobody could reach is first, with its reason and no number — a 0
// would read as the worst host rather than one nobody looked at.
func TestFleetScreenPutsTheUnscannedHostFirstWithoutAScore(t *testing.T) {
	m := loadedFleet(t)
	if m.entries[0].Host != "nas" || m.entries[1].Host != "db1" {
		t.Fatalf("order = %v", []string{m.entries[0].Host, m.entries[1].Host, m.entries[2].Host})
	}
	out := m.render()
	for _, want := range []string{"could not scan", "Connection refused"} {
		if !strings.Contains(out, want) {
			t.Errorf("screen lacks %q:\n%s", want, out)
		}
	}
}

func TestFleetScreenShowsTheSelectedHostsFindings(t *testing.T) {
	m := loadedFleet(t)
	m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	out := m.render()
	if !strings.Contains(out, "ssh.rootlogin") || !strings.Contains(out, "ssh db1 hostveil") {
		t.Errorf("the selected host's findings and where to fix them are not shown:\n%s", out)
	}
}

func TestFleetScreenWhileScanning(t *testing.T) {
	m := newFleetModel(nil, nil, []string{"a"}, FleetOpts{Theme: theme.Default()})
	if !strings.Contains(m.render(), "Scanning") {
		t.Error("no progress note while scanning")
	}
}
