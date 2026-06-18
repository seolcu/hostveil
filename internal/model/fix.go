package model

// Fix is a remediation the program can apply for a Finding.
type Fix struct {
	ID                 string   `json:"id"`
	RuleID             string   `json:"rule_id"`
	Version            string   `json:"version"`
	Description        string   `json:"description"`
	Preview            string   `json:"preview"`
	Procedure          string   `json:"procedure"`
	RequiresRestart    []string `json:"requires_restart"`
	RequiresElevation  bool     `json:"requires_elevation"`
	RollbackSupported  bool     `json:"rollback_supported"`
}
