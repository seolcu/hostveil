package model

import "testing"

func leftFinding(id string, sev Severity, src Source, rem RemediationKind) Finding {
	f := NewFinding(id, "t", sev, src, rem)
	f.Remediation = rem
	return f
}

// The two parts after the fixes account for every point between AfterFixes
// and 100, each counted once, and each names how many findings hold it.
func TestPointsLeftAddsUpToTheGap(t *testing.T) {
	pending := leftFinding("compose.ds006", SeverityMedium, SourceCompose, RemediationAuto)
	pending.Fixed, pending.Pending = true, true
	findings := []Finding{
		leftFinding("ssh.rootlogin", SeverityHigh, SourceSSH, RemediationReview),
		leftFinding("accounts.uid0", SeverityHigh, SourceAccounts, RemediationManual),
		leftFinding("dockerd.group-members", SeverityMedium, SourceDockerd, RemediationManual),
		leftFinding("cve.unpatched-image", SeverityHigh, SourceCVE, RemediationUnavailable),
		pending,
	}
	b := ScoreReport(findings, nil)
	l := b.Left

	if got, want := int(l.Manual)+int(l.Unavailable), 100-int(b.AfterFixes); got != want {
		t.Errorf("manual %d + unavailable %d = %d, want the whole gap %d", l.Manual, l.Unavailable, got, want)
	}
	if l.ManualCount != 2 || l.UnavailableCount != 1 || l.PendingCount != 1 {
		t.Errorf("counts = manual %d, unavailable %d, pending %d; want 2, 1, 1",
			l.ManualCount, l.UnavailableCount, l.PendingCount)
	}
	if l.Manual == 0 || l.Unavailable == 0 || l.Pending == 0 {
		t.Errorf("every part held a finding and should carry points: %+v", l)
	}
	if l.Pending > b.AfterFixes-b.Overall {
		t.Errorf("pending %d is part of the %d between the score and AfterFixes", l.Pending, b.AfterFixes-b.Overall)
	}
	if !l.Any() {
		t.Error("Any() = false with points left")
	}
}

// A clean host and a host with nothing scanned have nothing left to explain.
func TestPointsLeftIsEmptyWithNothingToExplain(t *testing.T) {
	if l := ScoreReport(nil, nil).Left; l.Any() {
		t.Errorf("a clean host has points left: %+v", l)
	}
	states := map[Source]ScanState{SourceSSH: ScanSkipped}
	f := leftFinding("accounts.uid0", SeverityHigh, SourceAccounts, RemediationManual)
	if l := ScoreReport([]Finding{f}, states).Left; l.Any() {
		t.Errorf("an inapplicable score has points left: %+v", l)
	}
}
