package history

import (
	"testing"
	"time"
)

// The scan id format had three copies and no round trip: NewScanID wrote a
// literal, scanIDAt parsed a constant in another file, and the trend tests
// supply their own hand-written ids — so NewScanID's output had never once
// been handed to the code that reads it.
//
// The checkpoint half of the same contract is covered (idTime(NewID(…)) is
// asserted in history_test.go) and so is the ordering scanFiles relies on.
// This was the gap between them.
//
// A divergence here empties the trend and shortens "since last scan" to
// nothing, because ListReports skips every id it cannot date — quietly, with
// no error anywhere.
func TestAScanIDRoundTripsThroughTheCodeThatReadsIt(t *testing.T) {
	id := NewScanID()

	at, err := scanIDAt(id)
	if err != nil {
		t.Fatalf("scanIDAt(%q) = %v — the writer and the reader disagree about the format", id, err)
	}
	if d := time.Since(at); d < 0 || d > time.Minute {
		t.Errorf("the recovered time is %v away from now; the layout parsed but means something else", d)
	}
}
