package model

import "time"

// TUISessionExitReason is the locked enum for TUISession.exit_reason.
type TUISessionExitReason string

const (
	TUIExitUserQuit      TUISessionExitReason = "user-quit"
	TUIExitNoTTY         TUISessionExitReason = "no-tty"
	TUIExitInternalError TUISessionExitReason = "internal-error"
	TUIExitKilled        TUISessionExitReason = "killed"
)

// TUISession is a single hostveil tui invocation.
type TUISession struct {
	ID                string              `json:"id"`
	HostID            string              `json:"host_id"`
	StartedAt         time.Time           `json:"started_at"`
	EndedAt           *time.Time          `json:"ended_at,omitempty"`
	ExitReason        TUISessionExitReason `json:"exit_reason,omitempty"`
	FindingsExpanded  int                 `json:"findings_expanded"`
	FixActionsTriggered int                `json:"fix_actions_triggered"`
	TerminalCols      int                 `json:"terminal_cols"`
	TerminalRows      int                 `json:"terminal_rows"`
	ColorEnabled      bool                `json:"color_enabled"`
}
