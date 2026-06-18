package model

import "time"

// FixRecord is a persistent record of a Fix that has been applied.
type FixRecord struct {
	ID                string     `json:"id"`
	ScanRunID         string     `json:"scan_run_id"`
	FindingID         string     `json:"finding_id"`
	FixID             string     `json:"fix_id"`
	AppliedAt         time.Time  `json:"applied_at"`
	AffectedPath      string     `json:"affected_path"`
	BackupPath        string     `json:"backup_path,omitempty"`
	ProcedureUsed     string     `json:"procedure_used"`
	RequiresRestart   []string   `json:"requires_restart"`
	RestartDeferred   bool       `json:"restart_deferred"`
	RecommendedBy     string     `json:"recommended_by,omitempty"` // e.g. "ai:ollama:llama3"
	RolledBackAt      *time.Time `json:"rolled_back_at,omitempty"`
	RolledBackVia     string     `json:"rolled_back_via,omitempty"`
}
