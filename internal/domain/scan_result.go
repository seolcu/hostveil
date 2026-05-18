package domain

import "time"

type ScanMode int

const (
	ScanModeExplicit ScanMode = iota
	ScanModeLive
)

func (m ScanMode) String() string {
	switch m {
	case ScanModeExplicit:
		return "explicit"
	case ScanModeLive:
		return "live"
	default:
		return "unknown"
	}
}

type AdapterStatus int

const (
	AdapterPending AdapterStatus = iota
	AdapterAvailable
	AdapterMissing
)

type AdapterInfo struct {
	Name   string
	Status AdapterStatus
	Detail string
}

type ServiceSummary struct {
	Name  string
	Image string
}

type HostRuntimeInfo struct {
	Hostname       string
	DockerVersion  string
	Uptime         string
	LoadAverage    string
	Fail2ban       string
	Fail2banJails  int
	Fail2banBanned int
}

type ScanMetadata struct {
	ScanMode    ScanMode
	ComposeFile string
	HostRoot    string
	Services    []ServiceSummary
	Warnings    []string
	Adapters    []AdapterInfo
	HostRuntime *HostRuntimeInfo
	StartedAt   time.Time
	Duration    time.Duration
}

type ScanResult struct {
	Findings    []Finding
	ScoreReport ScoreReport
	Metadata    ScanMetadata
}

func (r *ScanResult) TotalFindings() int {
	return len(r.Findings)
}

func (r *ScanResult) FindingsBySeverity(sev Severity) int {
	count := 0
	for _, f := range r.Findings {
		if f.Severity == sev {
			count++
		}
	}
	return count
}
