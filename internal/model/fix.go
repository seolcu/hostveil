package model

import "time"

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

// BatchOutcome is the result of applying every eligible Auto fix at once.
type BatchOutcome struct {
	Applied  []string          `json:"applied"` // finding IDs fixed
	Skipped  []string          `json:"skipped"` // needed a choice or had no auto fix
	Failed   map[string]string `json:"failed"`  // finding ID -> error
	NewScore ScoreBreakdown    `json:"new_score"`
}

// RollbackOutcome is the result of rolling back a checkpoint. Unfixed and
// NewScore mirror FixOutcome's AlsoFixed/NewScore so a long-lived UI can
// refresh its list and gauge straight from the response, exactly as it
// does after an apply.
type RollbackOutcome struct {
	CheckpointID   string         `json:"checkpoint_id"`
	RestoredFiles  []string       `json:"restored_files"`
	RestartService string         `json:"restart_service,omitempty"`
	Unfixed        []string       `json:"unfixed,omitempty"` // findings no longer marked fixed
	NewScore       ScoreBreakdown `json:"new_score"`
}

// Checkpoint is a UI-facing view of an applied fix's restore point. It is
// the value type the engine hands to CLI, TUI, and web, so no UI has to
// import internal/history to render the applied-fix log or offer rollback.
// Files carries only the restored paths; the backup blobs behind them are
// the history package's business and must not reach a client.
//
// Reversible is a field rather than a method so it survives JSON: the web
// UI needs it to decide whether to offer a rollback button, and deriving
// the rule browser-side would put fix logic back in a UI.
type Checkpoint struct {
	ID             string     `json:"id"`
	FindingID      string     `json:"finding_id"`
	Label          string     `json:"label"`
	CreatedAt      time.Time  `json:"created_at"`
	Reversible     bool       `json:"reversible"`
	Files          []string   `json:"files,omitempty"`
	Diff           string     `json:"diff,omitempty"`
	RestartService string     `json:"restart_service,omitempty"`
	Commands       [][]string `json:"commands,omitempty"`
}
