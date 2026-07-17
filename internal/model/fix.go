package model

// FixPreview is the side-effect-free preview of a finding's fix: what each
// available action would change, computed without touching any live file
// or running any command.
type FixPreview struct {
	FindingID string          `json:"finding_id"`
	Label     string          `json:"label"`
	Kind      RemediationKind `json:"kind"`
	Actions   []ActionPreview `json:"actions"`
}

// ActionPreview describes one alternative of a fix.
type ActionPreview struct {
	Index    int        `json:"index"`
	Label    string     `json:"label"`
	Warning  string     `json:"warning,omitempty"`
	Type     string     `json:"type"` // "edit" | "exec"
	Path     string     `json:"path,omitempty"`
	Diff     string     `json:"diff,omitempty"`
	Commands [][]string `json:"commands,omitempty"`
}

// FixOutcome is the result of applying a fix action.
type FixOutcome struct {
	Success      bool           `json:"success"`
	Error        string         `json:"error,omitempty"`
	Diff         string         `json:"diff,omitempty"`
	CheckpointID string         `json:"checkpoint_id,omitempty"` // "" if nothing to roll back
	AlsoFixed    []string       `json:"also_fixed,omitempty"`    // cascaded finding IDs
	RestartHint  string         `json:"restart_hint,omitempty"`  // service the user may need to restart
	NewScore     ScoreBreakdown `json:"new_score"`
}

// RollbackOutcome is the result of rolling back a checkpoint.
type RollbackOutcome struct {
	CheckpointID   string   `json:"checkpoint_id"`
	RestoredFiles  []string `json:"restored_files"`
	RestartService string   `json:"restart_service,omitempty"`
}
