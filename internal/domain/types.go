// Package domain defines core types: Finding, Severity, Source, and scan progress.
package domain

import "strings"

type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

type Source int

const (
	SourceTrivy Source = iota
	SourceLynis
	SourceCompose
)

func (s Source) String() string {
	switch s {
	case SourceTrivy:
		return "trivy"
	case SourceLynis:
		return "lynis"
	case SourceCompose:
		return "compose"
	default:
		return "unknown"
	}
}

type RemediationKind int

const (
	RemediationAuto RemediationKind = iota
	RemediationReview
	RemediationUnavailable
	RemediationManual
)

func (r RemediationKind) IsFixable() bool {
	return r == RemediationAuto || r == RemediationReview
}

func (r RemediationKind) String() string {
	switch r {
	case RemediationAuto:
		return "auto"
	case RemediationReview:
		return "review"
	case RemediationUnavailable:
		return "unavailable"
	case RemediationManual:
		return "manual"
	default:
		return "unknown"
	}
}

func (r RemediationKind) Label() string {
	switch r {
	case RemediationAuto:
		return "Auto-fix"
	case RemediationReview:
		return "Review"
	case RemediationUnavailable:
		return "Unavailable"
	case RemediationManual:
		return "Manual"
	default:
		return "Unknown"
	}
}

type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	HowToFix    string            `json:"how_to_fix"`
	Severity    Severity          `json:"severity"`
	Source      Source            `json:"source"`
	Service     string            `json:"service"`
	Remediation RemediationKind   `json:"remediation"`
	Evidence    map[string]string `json:"evidence"`
	Metadata    map[string]string `json:"metadata"`
	Fixed       bool              `json:"fixed"`
}

func (f *Finding) IsFixable() bool {
	return f.Remediation.IsFixable()
}

func EscapeCSV(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		s = strings.ReplaceAll(s, `"`, `""`)
		return `"` + s + `"`
	}
	return s
}
