// Package model holds hostveil's pure value types: findings, severity,
// source domains, remediation classification, scoring, and the report
// snapshot returned by the engine. It has zero dependencies on other
// internal packages so every layer can import it freely.
package model

// Severity ranks how urgent a finding is. Lower numeric value = more
// severe, so the zero value is the most severe (Critical); callers must
// always set Severity explicitly when constructing a Finding.
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow

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
// The penalties are load-bearing: weight() divides them by criticalHalves,
// so 8/5/2/1 is what makes one Critical cost half of an axis's remaining
// credit. cmd/sitegen pins the ratio against the prose on the website.
var severityDefs = []severityDef{
	{SeverityCritical, "critical", "crit", 8},
	{SeverityHigh, "high", "high", 5},
	{SeverityMedium, "medium", "med", 2},
	{SeverityLow, "low", "low", 1},
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
// The miss path returns Medium's penalty rather than a row's, and it must
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

// ParseSeverity resolves a lowercase severity name.
func ParseSeverity(s string) (Severity, bool) {
	sev, ok := severityByName[s]
	return sev, ok
}

// MarshalJSON writes the name rather than the ordinal. See enum.go.
func (s Severity) MarshalJSON() ([]byte, error) { return marshalEnum(s.String()) }

// UnmarshalJSON accepts the name or the integer older snapshots hold.
func (s *Severity) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, "severity", severityByName, func(v Severity) bool {
		_, ok := severityIndex[v]
		return ok
	})
	if err != nil {
		return err
	}
	*s = v
	return nil
}
