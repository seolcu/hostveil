package model

import "testing"

func TestAfterFixesIsTheScoreWithEveryOfferedFixApplied(t *testing.T) {
	findings := []Finding{
		NewFinding("compose.ds018", "exposed", SeverityHigh, SourceCompose, RemediationAuto, WithService("a")),
		NewFinding("compose.ds016", "socket", SeverityHigh, SourceCompose, RemediationManual, WithService("b")),
		NewFinding("ssh.rootlogin", "root login", SeverityHigh, SourceSSH, RemediationReview),
	}
	states := map[Source]ScanState{SourceCompose: ScanDone, SourceSSH: ScanDone}
	b := ScoreReport(findings, states)

	if b.AfterFixes <= b.Overall {
		t.Errorf("AfterFixes %d should exceed Overall %d when fixes are offered", b.AfterFixes, b.Overall)
	}

	// The SSH axis has one Review finding and nothing else, so fixing it
	// clears the axis outright.
	for _, ax := range b.Axes {
		switch ax.Source {
		case SourceSSH:
			if ax.AfterFixes != 100 {
				t.Errorf("ssh axis after fixes = %d, want 100", ax.AfterFixes)
			}
		case SourceCompose:
			// One Auto and one Manual: better, but not clean.
			if ax.AfterFixes <= ax.Score {
				t.Errorf("compose axis after fixes = %d, not better than %d", ax.AfterFixes, ax.Score)
			}
			if ax.AfterFixes == 100 {
				t.Error("compose axis reports 100 after fixes while a Manual finding stands")
			}
		}
	}
}

// A fix that is applied and waiting on a restart is charged in Overall — that
// is the whole point of Pending — and it must still count as done in
// AfterFixes, which asks where the number lands once the fixes have done their
// work.
//
// Getting this wrong is silent and lands in exactly the wrong place. The
// domains whose fixes are never immediate are the same domains this figure
// matters most for: run `fix --all` on a container host and every compose fix
// goes pending at once, so a headroom that dropped them would collapse onto
// the score precisely when the operator has just done everything hostveil
// asked and wants to know what it bought. Every UI hides the figure when it
// equals the score, so the symptom is not a wrong number — it is the number
// disappearing.
func TestTheHeadroomStillCountsAFixThatIsWaitingOnARestart(t *testing.T) {
	pending := NewFinding("compose.ds018", "exposed", SeverityHigh, SourceCompose, RemediationAuto, WithService("a"))
	pending.Fixed = true
	pending.Pending = true

	states := map[Source]ScanState{SourceCompose: ScanDone}
	b := ScoreReport([]Finding{pending}, states)

	// Charged now: nothing on the host has changed yet.
	clean := ScoreReport(nil, states)
	if b.Overall >= clean.Overall {
		t.Errorf("a fix that is not in force is not being charged: %d, clean host is %d",
			b.Overall, clean.Overall)
	}
	// And credited in the headroom: the operator has done their part.
	if b.AfterFixes != clean.Overall {
		t.Errorf("AfterFixes = %d, want %d — the headroom dropped a fix that is already applied",
			b.AfterFixes, clean.Overall)
	}
	if b.AfterFixes <= b.Overall {
		t.Error("the headroom collapsed onto the score, so every UI now hides it")
	}
}

func TestAfterFixesEqualsTheScoreWhenNothingIsFixable(t *testing.T) {
	findings := []Finding{
		NewFinding("compose.ds016", "socket", SeverityHigh, SourceCompose, RemediationManual, WithService("b")),
		NewFinding("cve.unpatched-image", "no patch", SeverityMedium, SourceCVE, RemediationUnavailable, WithService("i")),
	}
	states := map[Source]ScanState{SourceCompose: ScanDone, SourceCVE: ScanDone}
	b := ScoreReport(findings, states)
	if b.AfterFixes != b.Overall {
		t.Errorf("nothing is fixable, so AfterFixes %d must equal Overall %d", b.AfterFixes, b.Overall)
	}
}

func TestAfterFixesDoesNotMutateTheCallersFindings(t *testing.T) {
	findings := []Finding{
		NewFinding("compose.ds018", "exposed", SeverityHigh, SourceCompose, RemediationAuto, WithService("a")),
	}
	ScoreReport(findings, map[Source]ScanState{SourceCompose: ScanDone})
	if findings[0].Fixed {
		t.Error("scoring marked the caller's finding Fixed")
	}
}
