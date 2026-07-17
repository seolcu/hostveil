package model

// Delta compares two scans so a re-run can show progress: what got fixed,
// what is new, and what still remains since last time.
type Delta struct {
	Resolved     []Finding `json:"resolved"` // present before, gone now
	New          []Finding `json:"new"`      // present now, absent before
	StillPresent int       `json:"still_present"`
}

// HasChanges reports whether anything changed between the two scans.
func (d Delta) HasChanges() bool { return len(d.Resolved) > 0 || len(d.New) > 0 }

// ComputeDelta diffs the active (unfixed) findings of prev and curr by key.
func ComputeDelta(prev, curr Report) Delta {
	prevKeys := activeKeySet(prev)
	currKeys := activeKeySet(curr)

	var d Delta
	for _, f := range activeFindings(prev) {
		if !currKeys[f.Key()] {
			d.Resolved = append(d.Resolved, f)
		}
	}
	for _, f := range activeFindings(curr) {
		if prevKeys[f.Key()] {
			d.StillPresent++
		} else {
			d.New = append(d.New, f)
		}
	}
	return d
}

func activeFindings(r Report) []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !f.Fixed {
			out = append(out, f)
		}
	}
	return out
}

func activeKeySet(r Report) map[string]bool {
	set := make(map[string]bool, len(r.Findings))
	for _, f := range r.Findings {
		if !f.Fixed {
			set[f.Key()] = true
		}
	}
	return set
}
