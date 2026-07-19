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

// The regression this exists for: aggregating CVEs per image gave the
// finding a stable Key(), so key-only diffing reported "still present"
// while the number of vulnerabilities behind it moved. Three new CVEs in
// an image is exactly the signal the per-CVE findings used to carry.
func TestComputeDeltaDetectsMovementUnderAStableKey(t *testing.T) {
	before := NewFinding("cve.outdated-image", "outdated", SeverityCritical,
		SourceCVE, RemediationReview, WithService("cloud/nextcloud"),
		WithEvidence("count", "3627"), WithEvidence("cves", "CVE-1, CVE-2"))
	after := NewFinding("cve.outdated-image", "outdated", SeverityCritical,
		SourceCVE, RemediationReview, WithService("cloud/nextcloud"),
		WithEvidence("count", "3630"), WithEvidence("cves", "CVE-1, CVE-2, CVE-3"))

	d := ComputeDelta(report(before), report(after))

	if len(d.Changed) != 1 {
		t.Fatalf("expected 1 changed finding, got %+v", d.Changed)
	}
	// The four buckets partition: a changed finding is not also "still present".
	if d.StillPresent != 0 {
		t.Errorf("still present = %d, want 0 — changed and unchanged must not overlap", d.StillPresent)
	}
	if len(d.Resolved) != 0 || len(d.New) != 0 {
		t.Errorf("a moved finding is neither resolved nor new: %+v", d)
	}
	if got := d.Changed[0].ChangedEvidence(); len(got) != 2 || got[0] != "count" || got[1] != "cves" {
		t.Errorf("changed evidence = %v, want [count cves] sorted", got)
	}
	if !d.HasChanges() {
		t.Error("a moved finding is a change")
	}
}

// A finding that got worse in place must not read as unchanged.
func TestComputeDeltaDetectsSeverityMovement(t *testing.T) {
	before := NewFinding("cve.outdated-image", "t", SeverityHigh, SourceCVE,
		RemediationReview, WithService("media/redis"))
	after := NewFinding("cve.outdated-image", "t", SeverityCritical, SourceCVE,
		RemediationReview, WithService("media/redis"))

	d := ComputeDelta(report(before), report(after))
	if len(d.Changed) != 1 {
		t.Fatalf("a severity change is a change, got %+v", d)
	}
	if len(d.Changed[0].ChangedEvidence()) != 0 {
		t.Error("no evidence moved; only severity did")
	}
}

// Prose is edited by releases, not by the host. Rewording a description
// must not make every finding on every machine report as changed.
func TestComputeDeltaIgnoresProse(t *testing.T) {
	before := NewFinding("ssh.rootlogin", "t", SeverityHigh, SourceSSH,
		RemediationReview, WithDescription("old wording"), WithHowToFix("old fix text"))
	after := NewFinding("ssh.rootlogin", "t", SeverityHigh, SourceSSH,
		RemediationReview, WithDescription("new wording"), WithHowToFix("new fix text"))

	d := ComputeDelta(report(before), report(after))
	if len(d.Changed) != 0 {
		t.Errorf("reworded prose is not a change on the host: %+v", d.Changed)
	}
	if d.StillPresent != 1 {
		t.Errorf("still present = %d, want 1", d.StillPresent)
	}
}

// The question the per-CVE findings used to answer: which ones are new.
func TestEvidenceListDeltaNamesMembers(t *testing.T) {
	before := NewFinding("cve.outdated-image", "t", SeverityHigh, SourceCVE,
		RemediationReview, WithService("cloud/nextcloud"),
		WithEvidence("cves", "CVE-1, CVE-2, CVE-3"))
	after := NewFinding("cve.outdated-image", "t", SeverityHigh, SourceCVE,
		RemediationReview, WithService("cloud/nextcloud"),
		WithEvidence("cves", "CVE-2, CVE-3, CVE-4, CVE-5"))

	d := ComputeDelta(report(before), report(after))
	if len(d.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %+v", d)
	}
	added, removed := d.Changed[0].EvidenceListDelta("cves")
	if len(added) != 2 || added[0] != "CVE-4" || added[1] != "CVE-5" {
		t.Errorf("added = %v, want [CVE-4 CVE-5] sorted", added)
	}
	if len(removed) != 1 || removed[0] != "CVE-1" {
		t.Errorf("removed = %v, want [CVE-1]", removed)
	}
}

// Reordering the same members is not a membership change, and must not be
// reported as one.
func TestEvidenceListDeltaIgnoresReordering(t *testing.T) {
	c := FindingChange{
		Previous: NewFinding("x", "t", SeverityHigh, SourceCVE, RemediationManual,
			WithEvidence("cves", "CVE-1, CVE-2")),
		Current: NewFinding("x", "t", SeverityHigh, SourceCVE, RemediationManual,
			WithEvidence("cves", "CVE-2, CVE-1")),
	}
	added, removed := c.EvidenceListDelta("cves")
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("reorder reported as membership change: +%v -%v", added, removed)
	}
}

// The convention is shared: a new passwordless account should be as legible
// as a new CVE, with no per-domain knowledge in the diff.
func TestEvidenceListDeltaIsNotCVESpecific(t *testing.T) {
	c := FindingChange{
		Previous: NewFinding("accounts.emptypassword", "t", SeverityCritical,
			SourceAccounts, RemediationManual, WithEvidence("accounts", "guest")),
		Current: NewFinding("accounts.emptypassword", "t", SeverityCritical,
			SourceAccounts, RemediationManual, WithEvidence("accounts", "guest, backup")),
	}
	added, _ := c.EvidenceListDelta("accounts")
	if len(added) != 1 || added[0] != "backup" {
		t.Errorf("added = %v, want [backup]", added)
	}
}
