package clirender

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func TestFleetTableNeverScoresAnUnscannedHost(t *testing.T) {
	high := model.NewFinding("ssh.rootlogin", "root", model.SeverityHigh, model.SourceSSH, model.RemediationReview)
	f := model.Fleet{Hosts: []model.FleetEntry{
		{Host: "web1", Report: &model.Report{Score: model.ScoreBreakdown{Overall: 92, Applicable: true}}},
		{Host: "db1", Report: &model.Report{Findings: []model.Finding{high}, Score: model.ScoreBreakdown{Overall: 41, Applicable: true}}},
		{Host: "nas", Error: "could not connect over SSH: Connection refused"},
	}}
	out := Fleet(f, Options{})
	lines := strings.Split(out, "\n")
	if !strings.HasPrefix(lines[1], "nas") || !strings.HasPrefix(lines[2], "db1") || !strings.HasPrefix(lines[3], "web1") {
		t.Fatalf("not worst first:\n%s", out)
	}
	if strings.Contains(lines[1], " 0 ") || !strings.Contains(lines[1], "Connection refused") {
		t.Errorf("an unscanned host must show its reason and no number: %q", lines[1])
	}
	if !strings.Contains(lines[2], "41") || !strings.Contains(out, "2 host(s) scanned, 1 could not be") {
		t.Errorf("table:\n%s", out)
	}
}
