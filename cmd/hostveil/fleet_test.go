package main

import (
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The fleet gate is scan's gate across hosts, in scan's order: a High
// anywhere is 1 whatever else happened, then any host nobody could scan is 3.
func TestFleetExitCode(t *testing.T) {
	high := model.NewFinding("ssh.rootlogin", "root", model.SeverityHigh, model.SourceSSH, model.RemediationReview)
	clean := model.FleetEntry{Host: "a", Report: &model.Report{}}
	withHigh := model.FleetEntry{Host: "b", Report: &model.Report{Findings: []model.Finding{high}}}
	down := model.FleetEntry{Host: "c", Error: "could not connect"}
	for name, tc := range map[string]struct {
		hosts []model.FleetEntry
		want  int
	}{
		"all clean":       {[]model.FleetEntry{clean}, exitClean},
		"a high":          {[]model.FleetEntry{clean, withHigh}, exitFindings},
		"a host down":     {[]model.FleetEntry{clean, down}, exitIncomplete},
		"high beats down": {[]model.FleetEntry{down, withHigh}, exitFindings},
	} {
		if got := fleetExitCode(model.Fleet{Hosts: tc.hosts}); got != tc.want {
			t.Errorf("%s: exit = %d, want %d", name, got, tc.want)
		}
	}
}
