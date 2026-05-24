package domain

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
)

func (s Source) String() string {
	switch s {
	case SourceTrivy:
		return "trivy"
	case SourceLynis:
		return "lynis"
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
	ID          string
	Title       string
	Description string
	HowToFix    string
	Severity    Severity
	Source      Source
	Service     string
	Remediation RemediationKind
	Evidence    map[string]string
}

func (f *Finding) IsFixable() bool {
	return f.Remediation.IsFixable()
}

type ScanResult struct {
	Findings []Finding
	Score    uint8
	Grade    string
}

func (r *ScanResult) TotalFindings() int {
	return len(r.Findings)
}
