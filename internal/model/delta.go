package model

import (
	"maps"
	"sort"
	"strings"
)

// Delta compares two scans so a re-run can show progress: what got fixed,
// what is new, what got worse or better in place, and what still remains
// since last time. The four are disjoint — a changed finding is not also
// counted as still present.
type Delta struct {
	Resolved     []Finding       `json:"resolved"` // present before, gone now
	New          []Finding       `json:"new"`      // present now, absent before
	Changed      []FindingChange `json:"changed"`  // same finding, different substance
	StillPresent int             `json:"still_present"`
}

// FindingChange is one finding that persisted across both scans but whose
// substance moved.
//
// It exists because a finding's identity is coarser than its content.
// Key() is (source, id, service), so an aggregate finding keeps one key
// while the thing it summarises changes underneath it: cve.outdated-image
// covers every fixable vulnerability in an image, and three new CVEs
// appearing there is a real event that key-only diffing cannot see.
type FindingChange struct {
	Previous Finding `json:"previous"`
	Current  Finding `json:"current"`
}

// ChangedEvidence returns the evidence keys whose values differ, sorted.
// Keys present on only one side count as changed.
func (c FindingChange) ChangedEvidence() []string {
	var keys []string
	seen := map[string]bool{}
	for k := range c.Previous.Evidence {
		seen[k] = true
	}
	for k := range c.Current.Evidence {
		seen[k] = true
	}
	for k := range seen {
		if c.Previous.Evidence[k] != c.Current.Evidence[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// EvidenceSeparator is the convention for list-valued evidence: checkers
// join multiple items with it (accounts' account names, fileperms' file
// list, firewall's available tools, cve's vulnerability IDs). The space is
// load-bearing — clirender wraps on whitespace, so a comma-only join would
// be one unbreakable word that overflows a terminal.
const EvidenceSeparator = ", "

// EvidenceListDelta reports which items entered and left a list-valued
// evidence entry, sorted. Both slices are empty when the value is not a
// list, or when it changed without its membership changing.
//
// This is what makes an aggregate finding's movement legible: cve.
// outdated-image keeps one key while the set of vulnerabilities behind it
// changes, and "which three CVEs are new" is the question the old per-CVE
// findings used to answer.
func (c FindingChange) EvidenceListDelta(key string) (added, removed []string) {
	before := splitEvidenceList(c.Previous.Evidence[key])
	after := splitEvidenceList(c.Current.Evidence[key])
	for item := range after {
		if !before[item] {
			added = append(added, item)
		}
	}
	for item := range before {
		if !after[item] {
			removed = append(removed, item)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func splitEvidenceList(s string) map[string]bool {
	out := map[string]bool{}
	if s == "" {
		return out
	}
	for _, item := range strings.Split(s, EvidenceSeparator) {
		if item = strings.TrimSpace(item); item != "" {
			out[item] = true
		}
	}
	return out
}

// changed reports whether two findings sharing a key differ in substance.
// Severity and evidence are compared; Description and HowToFix are not,
// because those are prose the codebase itself edits between releases and a
// reworded sentence is not a change on the host.
func changed(prev, curr Finding) bool {
	return prev.Severity != curr.Severity || !maps.Equal(prev.Evidence, curr.Evidence)
}

// HasChanges reports whether anything changed between the two scans.
func (d Delta) HasChanges() bool {
	return len(d.Resolved) > 0 || len(d.New) > 0 || len(d.Changed) > 0
}

// ComputeDelta diffs the active (unfixed) findings of prev and curr by key.
func ComputeDelta(prev, curr Report) Delta {
	prevByKey := activeByKey(prev)
	currKeys := activeKeySet(curr)

	var d Delta
	for _, f := range activeFindings(prev) {
		if !currKeys[f.Key()] {
			d.Resolved = append(d.Resolved, f)
		}
	}
	for _, f := range activeFindings(curr) {
		before, existed := prevByKey[f.Key()]
		switch {
		case !existed:
			d.New = append(d.New, f)
		case changed(before, f):
			d.Changed = append(d.Changed, FindingChange{Previous: before, Current: f})
		default:
			d.StillPresent++
		}
	}
	return d
}

func activeByKey(r Report) map[string]Finding {
	out := make(map[string]Finding, len(r.Findings))
	for _, f := range r.Findings {
		if !f.Fixed {
			out[f.Key()] = f
		}
	}
	return out
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
