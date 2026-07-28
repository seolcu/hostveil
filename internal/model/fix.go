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
	RestartHint  string         `json:"restart_hint,omitempty"`  // service the user may need to restart
	NewScore     ScoreBreakdown `json:"new_score"`

	// Verified is what re-running the finding's own domain found, and
	// VerifyNote carries the reason when it could not be established.
	// Applying a fix marks the finding Fixed either way; these say whether
	// anything actually confirmed it.
	Verified FixVerification `json:"verified"`
	// VerifyMessage is the sentence every interface shows, rendered once by
	// the engine from Verified and RestartHint. The three outcome summaries
	// already phrase the same fields three different ways; this distinction
	// is subtle enough that three attempts at it would mean three different
	// claims.
	VerifyMessage string `json:"verify_message,omitempty"`
	// VerifyNote is the checker's own reason when the re-check could not
	// run — shown under the message, not instead of it.
	VerifyNote string `json:"verify_note,omitempty"`
}

// BatchOutcome is the result of applying every eligible Auto fix at once.
type BatchOutcome struct {
	Applied []string          `json:"applied"` // finding IDs fixed
	Skipped []string          `json:"skipped"` // needed a choice or had no auto fix
	Failed  map[string]string `json:"failed"`  // finding ID -> error
	// Interrupted reports that the batch stopped early because the run was
	// cancelled, so Skipped holds findings nobody decided against — they were
	// simply never reached. A UI must say so: the checkpoints for whatever
	// did land are on disk, and an operator who thinks the batch completed
	// has no reason to go looking for them.
	Interrupted bool           `json:"interrupted,omitempty"`
	NewScore    ScoreBreakdown `json:"new_score"`
}

// RollbackOutcome is the result of rolling back a checkpoint. Unfixed and
// NewScore let a long-lived UI refresh its list and gauge straight from the
// response, exactly as NewScore does after an apply.
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

// FixVerification is what a re-check of the finding's own domain found
// after a fix was applied.
//
// It exists because "hostveil wrote the file" and "the finding is gone" are
// different claims, and until now only the first was ever established —
// markFixed set Fixed the moment an apply returned, and the score moved on
// that. That is the same gap Action.VerifyCmd closes before a write: this
// closes the one after it.
//
// It deliberately does not change whether the finding is marked Fixed. A
// persisted sysctl drop-in is correct and complete and the running kernel
// still reports the old value until the next boot, so a checker that still
// sees the finding is not evidence the fix failed. Reporting the two facts
// separately is honest; collapsing them would either call that fix broken
// or call an unverified one confirmed.
type FixVerification int

const (
	// VerifyNotRun means no re-check was attempted — the batch path, which
	// would otherwise re-run a checker once per fix.
	VerifyNotRun FixVerification = iota
	// VerifyGone means the domain was re-checked and no longer reports it.
	VerifyGone
	// VerifyStillPresent means the domain was re-checked and still reports
	// it. Not necessarily a failure: the change may need a restart or a
	// reboot to take effect.
	VerifyStillPresent
	// VerifyUnavailable means the re-check could not run or could not cover
	// its ground. "Could not look" is not "still broken", and it is not
	// "fixed" either.
	VerifyUnavailable
)

// String returns the lowercase name used in JSON and in every UI.
func (v FixVerification) String() string {
	switch v {
	case VerifyGone:
		return "gone"
	case VerifyStillPresent:
		return "still-present"
	case VerifyUnavailable:
		return "unavailable"
	default:
		return "not-run"
	}
}

// Note is the one sentence every interface shows for this result.
//
// It lives here because the three outcome summaries — the CLI's
// printOutcome, the TUI's applySummary, and the dashboard's flash — already
// phrase the same fields three different ways, and this one carries a
// distinction subtle enough that three attempts at it would produce three
// different meanings.
//
// "Still present" is deliberately not phrased as a failure. The commonest
// case is a change that is correct and not yet in force: a sysctl drop-in
// applies at the next boot, and sshd serves from the config it already
// loaded until it restarts.
func (v FixVerification) Note(restartHint string) string {
	switch v {
	case VerifyGone:
		return "Re-checked: the finding is gone."
	case VerifyStillPresent:
		if restartHint != "" {
			return "Re-checked: the finding is still reported — the change may not take effect until '" +
				restartHint + "' restarts."
		}
		return "Re-checked: the finding is still reported — the change may not take effect until a restart or reboot."
	case VerifyUnavailable:
		return "Could not re-check this domain, so the fix is unconfirmed."
	default:
		return ""
	}
}

// MarshalJSON emits the name rather than the integer, so a consumer of
// --json is not left mapping ordinals the way the dashboard once had to.
func (v FixVerification) MarshalJSON() ([]byte, error) {
	return []byte(`"` + v.String() + `"`), nil
}
