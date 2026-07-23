package clirender

import (
	"bytes"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// lastDrawnFrame returns the final line Progress actually rendered, ignoring
// the blank frame and trailing return it uses to clear the line on the way
// out. Output is "\r<frame>\r<frame>…\r<blanks>\r", so splitting leaves an
// empty first and last element and the clearing frame second from the end.
func lastDrawnFrame(out string) string {
	frames := strings.Split(out, "\r")
	if len(frames) < 3 {
		return ""
	}
	return frames[len(frames)-3]
}

// The scan printed nothing until it was entirely finished, so a Trivy-enabled
// host looked indistinguishable from a hang. Progress must name what is
// actually still working.
func TestProgressNamesRunningDomains(t *testing.T) {
	events := make(chan model.ScanEvent, ProgressBufferSize)
	events <- model.ScanEvent{Source: model.SourceCVE, State: model.ScanRunning}
	events <- model.ScanEvent{Source: model.SourceSSH, State: model.ScanRunning}
	close(events)

	var out bytes.Buffer
	Progress(&out, events)

	if !strings.Contains(out.String(), "cve") || !strings.Contains(out.String(), "ssh") {
		t.Errorf("progress did not name the running domains:\n%q", out.String())
	}
}

// A domain that has finished must leave the line, whatever it finished as —
// a skipped or failed checker is no longer something the user is waiting on.
func TestProgressDropsFinishedDomains(t *testing.T) {
	for _, end := range []model.ScanState{
		model.ScanDone, model.ScanSkipped, model.ScanDegraded, model.ScanError,
	} {
		events := make(chan model.ScanEvent, ProgressBufferSize)
		events <- model.ScanEvent{Source: model.SourceCVE, State: model.ScanRunning}
		events <- model.ScanEvent{Source: model.SourceSSH, State: model.ScanRunning}
		events <- model.ScanEvent{Source: model.SourceCVE, State: end}
		close(events)

		var out bytes.Buffer
		Progress(&out, events)

		final := lastDrawnFrame(out.String())
		if strings.Contains(final, "cve") {
			t.Errorf("a %v domain stayed on the line: %q", end, final)
		}
		if !strings.Contains(final, "ssh") {
			t.Errorf("the still-running domain left the line: %q", final)
		}
	}
}

// The report is printed straight after this returns, so the progress line
// must not still be on screen underneath it.
func TestProgressClearsItsLine(t *testing.T) {
	events := make(chan model.ScanEvent, ProgressBufferSize)
	events <- model.ScanEvent{Source: model.SourceCompose, State: model.ScanRunning}
	close(events)

	var out bytes.Buffer
	Progress(&out, events)

	got := out.String()
	if !strings.HasSuffix(got, "\r") {
		t.Errorf("progress did not return the cursor to the start of the line: %q", got)
	}
	tail := got[strings.LastIndex(got[:len(got)-1], "\r")+1 : len(got)-1]
	if strings.TrimSpace(tail) != "" {
		t.Errorf("progress left %q on screen instead of blanking it", tail)
	}
}

// A shrinking line must blank the tail of the longer one it replaces, or the
// leftover characters read as domains still running.
func TestProgressBlanksTheTailOfALongerLine(t *testing.T) {
	events := make(chan model.ScanEvent, ProgressBufferSize)
	events <- model.ScanEvent{Source: model.SourceCompose, State: model.ScanRunning}
	events <- model.ScanEvent{Source: model.SourceFilePerms, State: model.ScanRunning}
	events <- model.ScanEvent{Source: model.SourceFilePerms, State: model.ScanDone}
	close(events)

	var out bytes.Buffer
	Progress(&out, events)

	shrunk := lastDrawnFrame(out.String())
	if strings.Contains(shrunk, "fileperms") {
		t.Errorf("the finished domain was still readable after the redraw: %q", shrunk)
	}
	if len(shrunk) < len("scanning: compose fileperms") {
		t.Errorf("redraw %q is shorter than the line it replaced, leaving characters behind", shrunk)
	}
}

// Nothing to report is not a reason to emit control characters into a
// terminal that may be showing something else.
func TestProgressWithNoEventsWritesNothing(t *testing.T) {
	events := make(chan model.ScanEvent)
	close(events)

	var out bytes.Buffer
	Progress(&out, events)

	if out.Len() != 0 {
		t.Errorf("wrote %q for an empty scan", out.String())
	}
}
