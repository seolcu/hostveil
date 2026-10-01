package model

import "sort"

// FleetEntry is one host's answer to a fleet scan: its report, or why there
// is none.
//
// Exactly one of Report and Error is set. A host that could not be reached,
// has no hostveil, or answered with something that is not a report carries
// an Error and never a score — the same rule every domain follows about "I
// could not look", one level up.
type FleetEntry struct {
	Host   string  `json:"host"`
	Report *Report `json:"report,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// Fleet is a set of hosts scanned over SSH, in the order they were named.
type Fleet struct {
	Hosts []FleetEntry `json:"hosts"`
}

// WorstFirst returns the entries ordered for a reader deciding where to look
// first: hosts that could not be scanned, then the rest by overall score
// ascending, with a host whose score is not applicable after every scored
// one. Ties keep the order the hosts were named in.
func (f Fleet) WorstFirst() []FleetEntry {
	out := append([]FleetEntry(nil), f.Hosts...)
	rank := func(e FleetEntry) (int, int) {
		switch {
		case e.Report == nil:
			return 0, 0
		case !e.Report.Score.Applicable:
			return 2, 0
		default:
			return 1, int(e.Report.Score.Overall)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ci, si := rank(out[i])
		cj, sj := rank(out[j])
		if ci != cj {
			return ci < cj
		}
		return si < sj
	})
	return out
}
