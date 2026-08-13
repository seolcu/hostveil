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
