package model

import "testing"

func report(findings ...Finding) Report { return Report{Findings: findings} }

func TestComputeDelta(t *testing.T) {
	a := NewFinding("compose.ds001", "a", SeverityHigh, SourceCompose, RemediationManual, WithService("app"))
	b := NewFinding("ssh.rootlogin", "b", SeverityHigh, SourceSSH, RemediationReview)
	c := NewFinding("firewall.inactive", "c", SeverityHigh, SourceFirewall, RemediationManual)

	prev := report(a, b) // had a, b
	curr := report(b, c) // b remains, c is new, a resolved

	d := ComputeDelta(prev, curr)
	if len(d.Resolved) != 1 || d.Resolved[0].ID != "compose.ds001" {
		t.Errorf("resolved = %+v", d.Resolved)
	}
	if len(d.New) != 1 || d.New[0].ID != "firewall.inactive" {
		t.Errorf("new = %+v", d.New)
	}
	if d.StillPresent != 1 {
		t.Errorf("still present = %d, want 1", d.StillPresent)
	}
	if !d.HasChanges() {
		t.Error("expected HasChanges")
	}
}

func TestComputeDeltaFixedFindingsResolved(t *testing.T) {
	a := NewFinding("compose.ds001", "a", SeverityHigh, SourceCompose, RemediationAuto, WithService("app"))
	prev := report(a)
	fixed := a
	fixed.Fixed = true
	curr := report(fixed) // same finding, now marked fixed → resolved

	d := ComputeDelta(prev, curr)
	if len(d.Resolved) != 1 {
		t.Errorf("a fixed finding should count as resolved, got %+v", d)
	}
}
