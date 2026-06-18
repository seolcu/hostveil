// Package model defines the canonical data types for hostveil.
// The structs here are persisted to state.db and serialized into the
// JSON report; the field names and JSON tags are locked by
// tests/contract/report_json_test.go.
package model

import "time"

// Severity is the locked enum for finding / vulnerability severity.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid reports whether s is one of the four locked severities.
func (s Severity) Valid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Host is the Linux machine the program runs against.
type Host struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	OSFamily    string    `json:"os_family"` // debian | rhel | arch | alpine | other
	OSVersion   string    `json:"os_version,omitempty"`
	Kernel      string    `json:"kernel"`
	Arch        string    `json:"arch"` // amd64 | arm64 | 386 | armv7
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}
