package domain

import "strings"

type RemediationKind int

const (
	RemediationManual RemediationKind = iota
	RemediationAuto
	RemediationReview
)

func (r RemediationKind) String() string {
	switch r {
	case RemediationManual:
		return "manual"
	case RemediationAuto:
		return "auto"
	case RemediationReview:
		return "review"
	default:
		return "unknown"
	}
}

func ParseRemediation(s string) (RemediationKind, bool) {
	switch strings.ToLower(s) {
	case "manual", "none":
		return RemediationManual, true
	case "auto", "safe":
		return RemediationAuto, true
	case "review", "guided":
		return RemediationReview, true
	default:
		return 0, false
	}
}

func (r RemediationKind) Label() string {
	switch r {
	case RemediationManual:
		return "Manual"
	case RemediationAuto:
		return "Auto Fix"
	case RemediationReview:
		return "Review Required"
	default:
		return "Unknown"
	}
}
