package check

import (
	"errors"
	"strings"
	"testing"
)

// Nothing missed is not a degraded domain. A ledger that returned a
// PartialError for a fully covered scan would mark every clean host Degraded
// and drag its axis down for nothing.
func TestCoverageWithNoGapsIsNotAnError(t *testing.T) {
	var cov Coverage
	cov.Covered(7)
	if err := cov.Err(); err != nil {
		t.Errorf("a complete scan produced %v", err)
	}

	// The zero value too: a checker that examined nothing and missed nothing
	// (a host with no containers) is clean, not partial.
	var empty Coverage
	if err := empty.Err(); err != nil {
		t.Errorf("the zero ledger produced %v", err)
	}
}

// The whole reason this type exists. Recording two gaps must report two —
// the bug it replaces was a checker returning at the first one, which made
// the second invisible in both the reason and the counters.
func TestCoverageReportsEveryGap(t *testing.T) {
	var cov Coverage
	cov.Covered(4)
	cov.Missed(2, "cannot parse two compose files")
	cov.Missed(1, "one image would not scan")

	var partial *PartialError
	if err := cov.Err(); !errors.As(err, &partial) {
		t.Fatalf("want a PartialError, got %v", err)
	}
	if partial.Covered != 4 || partial.Total != 7 {
		t.Errorf("coverage = %d/%d, want 4/7", partial.Covered, partial.Total)
	}
	for _, want := range []string{"cannot parse two compose files", "one image would not scan"} {
		if !strings.Contains(partial.Reason, want) {
			t.Errorf("reason %q is missing %q", partial.Reason, want)
		}
	}
	// Recording order is the checker's choice of emphasis, so it is kept.
	if !strings.HasPrefix(partial.Reason, "cannot parse two compose files; ") {
		t.Errorf("reasons were reordered or joined wrongly: %q", partial.Reason)
	}
}

// A gap with no unit of its own still degrades the domain. "Cannot enumerate
// the containers started outside Compose" cannot count what it failed to
// list, and demanding a number would have meant either inventing one or
// dropping the gap.
func TestCoverageCountlessGapStillDegrades(t *testing.T) {
	var cov Coverage
	cov.Covered(3)
	cov.Missed(0, "cannot enumerate standalone containers")

	err := cov.Err()
	if err == nil {
		t.Fatal("a gap with no unit count was treated as full coverage")
	}
	// And it must not read as a complete scan. Covered == Total here, which
	// is exactly the case that used to print "(covered 3 of 3)" beside a
	// sentence saying coverage was partial.
	if strings.Contains(err.Error(), "covered") {
		t.Errorf("a countless gap claimed a coverage fraction: %q", err.Error())
	}
}

// Units missed for a reason another entry already gave still lower the
// fraction, but must not repeat the sentence.
func TestCoverageSuppressedReasonStillCounts(t *testing.T) {
	var cov Coverage
	cov.Covered(1)
	cov.Missed(1, "cannot read the docker socket")
	cov.Missed(1, "")

	var partial *PartialError
	if err := cov.Err(); !errors.As(err, &partial) {
		t.Fatalf("want a PartialError, got %v", err)
	}
	if partial.Covered != 1 || partial.Total != 3 {
		t.Errorf("coverage = %d/%d, want 1/3", partial.Covered, partial.Total)
	}
	if strings.Count(partial.Reason, ";") != 0 {
		t.Errorf("the suppressed reason was emitted anyway: %q", partial.Reason)
	}
}

// A ledger whose only entries are suppressed cannot degrade a domain on a
// sentence it declines to say. Reaching this means every such gap's cause was
// already stated by a reason that is itself absent, which no checker does.
func TestCoverageOnlySuppressedReasonsIsClean(t *testing.T) {
	var cov Coverage
	cov.Covered(1)
	cov.Missed(1, "")
	if err := cov.Err(); err != nil {
		t.Errorf("a ledger with no sayable reason produced %v", err)
	}
}
