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
)

// IsFixable reports whether hostveil can offer to apply a fix. Unset,
// Manual, and Unavailable are all non-fixable.
func (r RemediationKind) IsFixable() bool {
	return r == RemediationAuto || r == RemediationReview
}

// Valid reports whether the kind was classified (i.e. not the zero value).
func (r RemediationKind) Valid() bool {
	return r != RemediationUnset
}

// String returns the stable lowercase name used in exports.
func (r RemediationKind) String() string {
	switch r {
	case RemediationAuto:
		return "auto"
	case RemediationReview:
		return "review"
	case RemediationManual:
		return "manual"
	case RemediationUnavailable:
		return "unavailable"
	default:
		return "unset"
	}
}

// Label returns the human-facing label shown in the UIs.
func (r RemediationKind) Label() string {
	switch r {
	case RemediationAuto:
		return "Auto-fix"
	case RemediationReview:
		return "Review"
	case RemediationManual:
		return "Manual"
	case RemediationUnavailable:
		return "Unavailable"
	default:
		return "Unclassified"
	}
}
