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

func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical, true
	case "high":
		return SeverityHigh, true
	case "medium":
		return SeverityMedium, true
	case "low":
		return SeverityLow, true
	default:
		return 0, false
	}
}

func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
}

func (s Severity) Color() string {
	switch s {
	case SeverityCritical:
		return "#f7768e"
	case SeverityHigh:
		return "#ff9e64"
	case SeverityMedium:
		return "#e0af68"
	case SeverityLow:
		return "#9ece6a"
	default:
		return "#565f89"
	}
}
