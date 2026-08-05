// Package model holds hostveil's pure value types: findings, severity,
// source domains, remediation classification, scoring, and the report
// snapshot returned by the engine. It has zero dependencies on other
// internal packages so every layer can import it freely.
package model

import "encoding/json"

// Severity ranks how urgent a finding is. Lower numeric value = more
// severe, so the zero value is the most severe (Exposed); callers must
// always set Severity explicitly when constructing a Finding.
//
// There are three levels and they answer *how urgent*, not *how bad*.
//
// The four this replaces — Critical/High/Medium/Low — came from Trivy, and
// hostveil kept them so a CVE's rating could pass straight through. That
// reason is gone: CVEs are rolled up per image now, so no individual rating
// survives into a finding, and outside the CVE domain the four levels were
// asking a question nobody can answer from a config file. "How bad is a
// container running as root" has no number; it depends entirely on what the
// container is. What a scanner *can* see is how much stands between an
// attacker and this problem right now, and that is what these three levels
// measure.
//
// The names are deliberately not adjectives about the finding. "Critical"
// invites an argument about whether something is critical; "Exposed" is a
// claim about the host that is either true or false.
type Severity int

const (
	// SeverityExposed: something is reachable or usable right now, from
	// off-host, by someone who holds nothing. An open service with no
	// authentication, a login with no password, a container that has already
	// been handed host root. Nothing has to be broken first.
	SeverityExposed Severity = iota

	// SeverityWeak: a boundary that gives way to a foothold, a guessed
	// credential, or a local account. The attacker needs something they do
	// not have yet, and this is what makes getting it worthwhile.
	SeverityWeak

	// SeverityHardening: defence in depth. No known path today; it narrows
	// what a future compromise reaches.
	SeverityHardening

	severityCount // sentinel, not a severity; keep last
)

type severityDef struct {
	sev     Severity
	name    string // lowercase name used in reports and exports
	abbr    string // short form for width-constrained surfaces
	penalty int    // per-finding score deduction
}

// severityDefs describes the enum once. Unlike the other tables here this
// one happens to start at 0, so its rows do line up with their values —
// which is exactly why the lookup is still keyed by the value column. Two
// tables in one package, one offset by a zero-value constant and one not,
// is how an index-by-position habit turns into a silent off-by-one.
//
// The penalties are load-bearing: weight() divides them by exposedHalves,
// so 8/2/1 is what makes one Exposed finding cost half of an axis's
// remaining credit. cmd/sitegen pins the ratio against the prose on the
// website.
//
// The gap between 8 and 2 is the point of the taxonomy. Under the four
// levels the top two were 8 and 5, which said a thing you can reach today
// and a thing you cannot are within a third of each other. They are not.
var severityDefs = []severityDef{
	{SeverityExposed, "exposed", "expo", 8},
	{SeverityWeak, "weak", "weak", 2},
	{SeverityHardening, "hardening", "hrdn", 1},
}

var severityIndex = indexBy(severityDefs, func(d severityDef) Severity { return d.sev })

// String returns the lowercase name used in reports and exports.
func (s Severity) String() string {
	if d, ok := severityIndex[s]; ok {
		return d.name
	}
	return "unknown"
}

// Abbr returns the short lowercase form for surfaces with a width budget —
// the TUI's finding rows (which upper-case it) and the dashboard's chips.
// Every abbreviation is at most four characters, because the TUI pads the
// column to that width and a longer one would shift every row.
func (s Severity) Abbr() string {
	if d, ok := severityIndex[s]; ok {
		return d.abbr
	}
	return "?"
}

// Penalty is the per-finding score deduction for this severity, summed
// per axis and capped in scoring.
//
// The miss path returns Weak's penalty rather than a row's, and it must
// stay written out: a table lookup that fell back to the zero value would
// return 0, and weight() would price an unrecognised severity at nothing.
// A finding that costs a perfect score nothing is the same lie as scoring
// a domain nobody could scan at 100.
func (s Severity) Penalty() int {
	if d, ok := severityIndex[s]; ok {
		return d.penalty
	}
	return 2
}

// AllSeverities lists every severity, most severe first. UIs that mirror
// the enum build their table from this.
func AllSeverities() []Severity {
	return columnOf(severityDefs, func(d severityDef) Severity { return d.sev })
}

var severityByName = nameIndex(severityDefs,
	func(d severityDef) Severity { return d.sev },
	func(d severityDef) string { return d.name })

// legacySeverities maps the four-level scale onto the three, for reading
// scans written before the change.
//
// Both halves are needed and they cannot share a path. A *name* is
// unambiguous — "medium" was never one of the new levels, so it can only be
// the old scale. An *integer* is not: 2 meant Medium then and would mean
// Hardening now, and the same file cannot say which it is. So integers are
// always read as the old scale, which is sound because the release that
// introduced names is the last one that ever wrote an integer. A snapshot
// with a number in it predates the rename by construction.
var legacySeverities = map[string]Severity{
	"critical": SeverityExposed,
	"high":     SeverityExposed,
	"medium":   SeverityWeak,
	"low":      SeverityHardening,
}

var legacySeverityOrdinals = map[int]Severity{
	0: SeverityExposed,   // critical
	1: SeverityExposed,   // high
	2: SeverityWeak,      // medium
	3: SeverityHardening, // low
}

// ParseSeverity resolves a lowercase severity name, including the four
// names this scale replaced.
func ParseSeverity(s string) (Severity, bool) {
	if sev, ok := severityByName[s]; ok {
		return sev, true
	}
	sev, ok := legacySeverities[s]
	return sev, ok
}

// MarshalJSON writes the name rather than the ordinal. See enum.go.
func (s Severity) MarshalJSON() ([]byte, error) { return marshalEnum(s.String()) }

// UnmarshalJSON accepts a current name, one of the four names it replaced,
// or the ordinal of the old four-level scale.
func (s *Severity) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var name string
		if err := json.Unmarshal(data, &name); err != nil {
			return err
		}
		sev, ok := ParseSeverity(name)
		if !ok {
			return errUnknownEnum("severity", name)
		}
		*s = sev
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return errEnumShape("severity", err)
	}
	sev, ok := legacySeverityOrdinals[n]
	if !ok {
		return errUnknownOrdinal("severity", n)
	}
	*s = sev
	return nil
}
