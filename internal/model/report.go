package model

import "sort"

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
