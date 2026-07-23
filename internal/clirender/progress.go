package clirender

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// ProgressBufferSize is how much room a caller should give the event
// channel it passes to Engine.Scan.
//
// The engine drops an event rather than let a slow consumer stall a scan
// (see check.emit), so the buffer is what keeps that safety valve from
// quietly costing progress lines. Two events per domain is the whole traffic
// of a scan; this is comfortably more.
const ProgressBufferSize = 64

// Progress renders live scan progress to w until events is closed.
//
// It exists because a scan printed nothing at all until it was completely
// finished. Engine.Scan has always taken this channel and every caller
// passed nil, so on a host with Trivy installed `hostveil scan` sat on a
// blank terminal for minutes with no way to tell it apart from a hang.
//
// The output is one line, rewritten in place with a carriage return, naming
// the domains still running. It is cleared before returning so whatever the
// caller prints next starts on a clean line — the progress display is
// scaffolding for the wait, not part of the report.
//
// Callers send this to stderr. Progress on stdout would corrupt `--json` and
// anything piped to a file, which is the case the exit code exists to serve.
func Progress(w io.Writer, events <-chan model.ScanEvent) {
	running := map[model.Source]bool{}
	var lastWidth int

	redraw := func() {
		names := make([]string, 0, len(running))
		for src := range running {
			names = append(names, src.String())
		}
		sort.Strings(names) // map order would make the line jitter between redraws

		line := ""
		if len(names) > 0 {
			line = "scanning: " + strings.Join(names, " ")
		}
		// Pad to the previous width so a shrinking line does not leave the
		// tail of the longer one behind it on screen.
		pad := ""
		if n := lastWidth - len(line); n > 0 {
			pad = strings.Repeat(" ", n)
		}
		fmt.Fprintf(w, "\r%s%s", line, pad)
		lastWidth = len(line)
	}

	for ev := range events {
		if ev.State == model.ScanRunning {
			running[ev.Source] = true
		} else {
			delete(running, ev.Source)
		}
		redraw()
	}

	// Clear the line entirely; the report follows.
	if lastWidth > 0 {
		fmt.Fprintf(w, "\r%s\r", strings.Repeat(" ", lastWidth))
	}
}
