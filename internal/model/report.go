package model

import (
	"sort"
	"strings"
	"time"
)

// ScanState is the lifecycle state of one domain's checker during a scan.
type ScanState int

const (
	ScanPending  ScanState = iota // not started
	ScanRunning                   // checker executing
	ScanDone                      // completed successfully
	ScanSkipped                   // dependency absent (e.g. Trivy not installed) — not an error
	ScanDegraded                  // ran but produced a partial result
	ScanError                     // failed
)

// String returns the lowercase state name for display and exports.
func (s ScanState) String() string {
	switch s {
	case ScanRunning:
		return "running"
	case ScanDone:
		return "done"
	case ScanSkipped:
		return "skipped"
	case ScanDegraded:
		return "degraded"
	case ScanError:
		return "error"
	default:
		return "pending"
	}
}

// Ran reports whether the checker actually executed and contributed to
// scoring (Done or Degraded). Skipped/Error/Pending did not.
func (s ScanState) Ran() bool {
	return s == ScanDone || s == ScanDegraded
}

// DomainResult records how one checker fared during a scan.
type DomainResult struct {
	Source       Source    `json:"source"`
	State        ScanState `json:"state"`
	Reason       string    `json:"reason,omitempty"` // why skipped/degraded/errored
	FindingCount int       `json:"finding_count"`
}

// ScanEvent is streamed as each checker changes state so UIs can render
// live per-domain progress.
type ScanEvent struct {
	Source Source    `json:"source"`
	State  ScanState `json:"state"`
	Reason string    `json:"reason,omitempty"`
}

// Report is an immutable snapshot of a completed (or in-progress) scan.
// It is the value type the engine hands to every UI.
type Report struct {
	Findings []Finding      `json:"findings"`
	Score    ScoreBreakdown `json:"score"`
	Domains  []DomainResult `json:"domains"`
}

// Filter selects a subset of findings for display.
type Filter struct {
	Source       Source // SourceUnset = any
	MinSeverity  *Severity
	FixableOnly  bool
	IncludeFixed bool
}

// Matches reports whether a finding passes the filter.
func (flt Filter) Matches(f Finding) bool {
	if !flt.IncludeFixed && f.Fixed {
		return false
	}
	if flt.Source != SourceUnset && f.Source != flt.Source {
		return false
	}
	if flt.MinSeverity != nil && f.Severity > *flt.MinSeverity {
		return false
	}
	if flt.FixableOnly && !f.IsFixable() {
		return false
	}
	return true
}

// Select returns the report's findings that pass the filter.
func (r Report) Select(flt Filter) []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if flt.Matches(f) {
			out = append(out, f)
		}
	}
	return out
}

// SortFindings orders findings by severity (most severe first), then
// source, then ID, for stable presentation across all UIs.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.ID < b.ID
	})
}

// ScorePoint is one past scan's headline score, for a trend.
//
// Applicable mirrors ScoreBreakdown.Applicable and must be carried, not
// flattened to a number: a scan where every domain was skipped or failed
// has no score at all, and rendering it as 0 would draw a cliff where the
// truth is "nobody could look". The same lie the aggregate score already
// refuses to tell, told again by a chart.
type ScorePoint struct {
	At         time.Time `json:"at"`
	Overall    uint8     `json:"overall"`
	Applicable bool      `json:"applicable"`
}

// Sparkline renders a score series as one line of block glyphs.
//
// It lives on the model rather than in either interface because both draw
// the same picture from the same points, and a bucketing rule written twice
// is the shape that has already gone wrong here twice — the severity
// palette before internal/ui/theme, the domain table before /domains.js.
// The TUI prints the string; the dashboard renders the same characters in a
// monospace span.
//
// Scores are bucketed against the fixed 0-100 range, never against the
// series' own min and max. Auto-scaling would turn a host that moved from
// 71 to 73 into a dramatic climb and one that sat at 42 all week into a
// flat line indistinguishable from a host at 4, which is a chart that lies
// about the only thing it is for.
//
// A scan with no applicable score contributes a gap rather than a bar. It
// is not a zero — nobody could look — and drawing it as the lowest bucket
// would be the same lie the aggregate score refuses to tell.
func Sparkline(points []ScorePoint) string {
	// Runes, not a string: every bar is three bytes, so indexing by
	// len("▁▂▃▄▅▆▇█") would reach for element 24 of an eight-element ramp.
	bars := []rune("▁▂▃▄▅▆▇█")
	const gap = '·'

	var b strings.Builder
	for _, p := range points {
		if !p.Applicable {
			b.WriteRune(gap)
			continue
		}
		// 0 lands in the first bucket and 100 in the last; the division is
		// by 100 rather than by len(bars)+1 so a perfect score is a full
		// bar, with the top clamped rather than overflowing.
		i := int(p.Overall) * len(bars) / 100
		if i >= len(bars) {
			i = len(bars) - 1
		}
		b.WriteRune(bars[i])
	}
	return b.String()
}
