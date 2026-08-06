package model

import "testing"

// Each enum in this package is described by one table, and each table is
// reachable only through the constants declared beside it. That makes one
// failure mode invisible to every other test: a constant added to the block
// with no row in the table simply never appears in the All* projection, so
// every test that iterates All* passes without ever seeing it — vacuously,
// and in the direction that reports the missing thing as fine.
//
// These tests are the ones that walk the *const range* instead, from the
// first constant to the sentinel. They are the only guard that a new
// constant was actually described.

// The domain enum, which has the most tables behind it and the worst
// failure when one of them is missed: a Source with no description scores
// nothing, filters as nothing, and renders as a bare integer, while every
// test that enters through AllSources reports the host as fine.
func TestEverySourceConstHasATableRow(t *testing.T) {
	inAll := map[Source]bool{}
	for _, s := range AllSources() {
		inAll[s] = true
	}
	axes := map[Source]bool{}
	for _, ax := range ScoreReport(nil, nil).Axes {
		axes[ax.Source] = true
	}

	for s := SourceUnset + 1; s < sourceCount; s++ {
		if !s.Valid() {
			t.Errorf("source %d is declared but not Valid — its findings are dropped after the scan", int(s))
		}
		if s.String() == "unset" {
			t.Errorf("source %d has no String() name", int(s))
		}
		if s.Label() == "" {
			t.Errorf("source %q (%d) has no Label() — it renders as a bare integer", s, int(s))
		}
		if !inAll[s] {
			t.Errorf("source %q (%d) is missing from AllSources()", s, int(s))
		}
		if !axes[s] {
			t.Errorf("source %q (%d) has no scoring axis", s, int(s))
		}
	}

	if got := len(AllSources()); got != int(sourceCount)-1 {
		t.Errorf("AllSources has %d entries, %d domain constants declared", got, int(sourceCount)-1)
	}
	// The sentinel is not a domain and must never pass for one.
	if sourceCount.Valid() || sourceCount.Label() != "" {
		t.Error("sourceCount is a sentinel, not a domain")
	}
}

func TestEverySeverityConstHasATableRow(t *testing.T) {
	for s := SeverityHigh; s < severityCount; s++ {
		if _, ok := severityIndex[s]; !ok {
			t.Errorf("severity %d has no severityDefs row", int(s))
			continue
		}
		if s.String() == "unknown" {
			t.Errorf("severity %d falls through String() to the miss path", int(s))
		}
		if s.Abbr() == "?" {
			t.Errorf("severity %q falls through Abbr() to the miss path", s)
		}
		if len(s.Abbr()) > 4 {
			t.Errorf("severity %q has abbreviation %q, wider than the 4-column budget the TUI pads to",
				s, s.Abbr())
		}
		if s.Penalty() <= 0 {
			t.Errorf("severity %q has penalty %d; a finding that costs nothing is not a finding",
				s, s.Penalty())
		}
	}
	if got := len(AllSeverities()); got != int(severityCount) {
		t.Errorf("AllSeverities has %d entries, %d constants declared", got, int(severityCount))
	}
}

func TestEveryRemediationConstHasATableRow(t *testing.T) {
	for r := RemediationUnset; r < remediationCount; r++ {
		if _, ok := remediationIndex[r]; !ok {
			t.Errorf("remediation %d has no remediationDefs row", int(r))
			continue
		}
		if r != RemediationUnset && r.String() == "unset" {
			t.Errorf("remediation %d falls through String() to the miss path", int(r))
		}
		if r != RemediationUnset && r.Label() == "Unclassified" {
			t.Errorf("remediation %q falls through Label() to the miss path", r)
		}
	}
	if got := len(AllRemediationKinds()); got != int(remediationCount) {
		t.Errorf("AllRemediationKinds has %d entries, %d constants declared", got, int(remediationCount))
	}
}

func TestEveryScanStateConstHasATableRow(t *testing.T) {
	for s := ScanPending; s < scanStateCount; s++ {
		if _, ok := scanStateIndex[s]; !ok {
			t.Errorf("scan state %d has no scanStateDefs row", int(s))
			continue
		}
		if s != ScanPending && s.String() == "pending" {
			t.Errorf("scan state %d falls through String() to the miss path", int(s))
		}
		// Complete without Ran would mean a checker that covered all of
		// its ground yet contributed nothing to the score.
		if s.Complete() && !s.Ran() {
			t.Errorf("scan state %q is complete but did not run", s)
		}
	}
	if got := len(AllScanStates()); got != int(scanStateCount) {
		t.Errorf("AllScanStates has %d entries, %d constants declared", got, int(scanStateCount))
	}
}

// Names key the tables the dashboard is served, so a duplicate silently
// collapses two constants into one on the way to the browser.
func TestEnumNamesAreDistinct(t *testing.T) {
	t.Run("severity", func(t *testing.T) {
		assertDistinct(t, AllSeverities(), Severity.String)
		assertDistinct(t, AllSeverities(), Severity.Abbr)
	})
	t.Run("remediation", func(t *testing.T) {
		assertDistinct(t, AllRemediationKinds(), RemediationKind.String)
		assertDistinct(t, AllRemediationKinds(), RemediationKind.Label)
	})
	t.Run("scanstate", func(t *testing.T) {
		assertDistinct(t, AllScanStates(), ScanState.String)
	})
}

func assertDistinct[T comparable](t *testing.T, vals []T, name func(T) string) {
	t.Helper()
	seen := map[string]T{}
	for _, v := range vals {
		n := name(v)
		if prev, dup := seen[n]; dup {
			t.Errorf("%v and %v share the name %q", prev, v, n)
		}
		seen[n] = v
	}
}

// The miss paths are not decoration. Every one of these values can arrive
// from a corrupt snapshot or a caller's bad cast, and each method has to
// answer without reaching into a zero-value row.
func TestEnumMissPaths(t *testing.T) {
	for _, s := range []Severity{-1, severityCount, 99} {
		if s.String() != "unknown" {
			t.Errorf("Severity(%d).String() = %q, want unknown", int(s), s.String())
		}
		if s.Abbr() != "?" {
			t.Errorf("Severity(%d).Abbr() = %q, want ?", int(s), s.Abbr())
		}
		// The one that matters: a zero-value row would price this at 0,
		// making an unrecognised finding free.
		if s.Penalty() != 2 {
			t.Errorf("Severity(%d).Penalty() = %d, want 2 (Medium's)", int(s), s.Penalty())
		}
	}
	for _, r := range []RemediationKind{-1, remediationCount, 99} {
		if r.String() != "unset" || r.Label() != "Unclassified" {
			t.Errorf("RemediationKind(%d) = %q/%q, want unset/Unclassified", int(r), r.String(), r.Label())
		}
		if r.IsFixable() {
			t.Errorf("RemediationKind(%d) must not offer a fix", int(r))
		}
	}
	for _, s := range []ScanState{-1, scanStateCount, 99} {
		if s.String() != "pending" {
			t.Errorf("ScanState(%d).String() = %q, want pending", int(s), s.String())
		}
		// An unrecognised state has established nothing, so it must not
		// be scored and must not vouch for a clean host.
		if s.Ran() || s.Complete() {
			t.Errorf("ScanState(%d): Ran=%v Complete=%v, want both false", int(s), s.Ran(), s.Complete())
		}
	}
}
