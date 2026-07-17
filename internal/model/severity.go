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
)

// String returns the lowercase name used in reports and exports.
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

// Penalty is the per-finding score deduction for this severity, summed
// per axis and capped in scoring.
func (s Severity) Penalty() int {
	switch s {
	case SeverityCritical:
		return 8
	case SeverityHigh:
		return 5
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 2
	}
}
