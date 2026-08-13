package model

// RemediationKind classifies how a finding can be fixed.
//
// The zero value is RemediationUnset — deliberately inert. In hostveil v2
// the zero value was "Auto", so any Finding built without setting the
// field silently presented a fix button it never had. Here an
// unclassified finding is NOT fixable, and a validation pass rejects any
// Unset finding in a completed report, so the footgun cannot recur.
type RemediationKind int

const (
	RemediationUnset       RemediationKind = iota // 0 = not classified, not fixable
	RemediationAuto                               // exactly one mechanical action
	RemediationReview                             // multiple independent alternatives; user picks
	RemediationManual                             // guidance only, no automatable action
	RemediationUnavailable                        // known issue, no fix exists yet (e.g. CVE with no patch)

	remediationCount // sentinel, not a kind; keep last
)

type remediationDef struct {
	kind    RemediationKind
	name    string // stable lowercase name used in exports
	label   string // human-facing label shown in the UIs
	abbr    string // short form for surfaces with a width budget
	fixable bool   // hostveil can offer to apply something
}

// remediationDefs is the single description of the enum: name, label, and
// fixability were three switches over the same five constants.
//
// The kind is an explicit column and the lookup is built from it, never
// from the slice index. The numeric value is what reaches disk and the
// wire, so nothing may depend on a row's position — that is the invariant
// the whole enum-table shape has to protect.
//
// RemediationUnset has a row so the zero value has a name and a label of
// its own rather than falling out of a default arm. Its false fixability
// is not a judgement about the finding: an unclassified finding is not
// "known to have no fix", it is one nobody has classified, and both must
// refuse to offer a fix button.
var remediationDefs = []remediationDef{
	{RemediationUnset, "unset", "Unclassified", "?", false},
	{RemediationAuto, "auto", "Auto-fix", "auto", true},
	{RemediationReview, "review", "Review", "review", true},
	{RemediationManual, "manual", "Manual", "manual", false},
	{RemediationUnavailable, "unavailable", "Unavailable", "n/a", false},
}

var remediationIndex = indexBy(remediationDefs, func(d remediationDef) RemediationKind { return d.kind })

// IsFixable reports whether hostveil can offer to apply a fix. Unset,
// Manual, and Unavailable are all non-fixable.
func (r RemediationKind) IsFixable() bool {
	return remediationIndex[r].fixable
}

// Valid reports whether the kind was classified (i.e. not the zero value).
//
// This asks only about Unset, not about table membership. A value outside
// the enum entirely is a bug or a corrupt snapshot, and the right answer
// to that is a finding rendered "Unclassified" with no fix button — which
// is what the other three methods already do. Failing Valid instead would
// send it through Finding.Validate and drop it from the report, trading a
// visible oddity for a silent disappearance.
func (r RemediationKind) Valid() bool {
	return r != RemediationUnset
}

// Abbr returns the short lowercase form for surfaces with a width budget —
// the TUI's finding rows, which upper-case it.
//
// Every abbreviation is at most six characters, because the TUI pads the
// column to that width and a longer one would shift every row. That is the
// same contract Severity.Abbr carries, and the same reason.
//
// "n/a" rather than "none" for Unavailable: the finding is real and the
// absence is of a *fix*, which is what N/A says on the score axes already.
func (r RemediationKind) Abbr() string {
	if d, ok := remediationIndex[r]; ok {
		return d.abbr
	}
	return "?"
}

// String returns the stable lowercase name used in exports.
func (r RemediationKind) String() string {
	if d, ok := remediationIndex[r]; ok {
		return d.name
	}
	return "unset"
}

// Label returns the human-facing label shown in the UIs.
func (r RemediationKind) Label() string {
	if d, ok := remediationIndex[r]; ok {
		return d.label
	}
	return "Unclassified"
}

// AllRemediationKinds lists every kind in declaration order, Unset
// included. UIs that mirror the enum build their table from this.
func AllRemediationKinds() []RemediationKind {
	return columnOf(remediationDefs, func(d remediationDef) RemediationKind { return d.kind })
}

var remediationByName = nameIndex(remediationDefs,
	func(d remediationDef) RemediationKind { return d.kind },
	func(d remediationDef) string { return d.name })

// ParseRemediationKind resolves a stable lowercase kind name.
func ParseRemediationKind(s string) (RemediationKind, bool) {
	kind, ok := remediationByName[s]
	return kind, ok
}

// MarshalJSON writes the name rather than the ordinal. See enum.go.
func (r RemediationKind) MarshalJSON() ([]byte, error) { return marshalEnum(r.String()) }

// UnmarshalJSON accepts the name or the integer older snapshots hold.
func (r *RemediationKind) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, "remediation", remediationByName, func(v RemediationKind) bool {
		_, ok := remediationIndex[v]
		return ok
	})
	if err != nil {
		return err
	}
	*r = v
	return nil
}
