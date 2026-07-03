package history

import (
	"os"
	"path/filepath"
	"time"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

// ApplyWithCheckpoint runs a fix action and, for ActionEdit actions that
// touch a real file, wraps the run in a checkpoint: the target file is
// backed up before Apply runs, and a checkpoint recording the backup plus
// the resulting diff is saved on success. This is the single code path
// both the Web UI and the TUI must use to apply a fix, so that
// `hostveil rollback <id>` can restore either UI's changes — a fix
// applied without a checkpoint cannot be rolled back.
//
// f and finding must be non-nil. actionIdx is validated by f.Run.
func ApplyWithCheckpoint(f *fix.Fix, finding *domain.Finding, actionIdx int) fix.FixResult {
	if actionIdx < 0 || actionIdx >= len(f.Actions) {
		return fix.FixResult{Error: "invalid action index"}
	}
	action := f.Actions[actionIdx]

	cp := Checkpoint{
		ID:        CheckpointID(finding.ID),
		Timestamp: time.Now(),
		FindingID: finding.ID,
		Service:   finding.Service,
		Action:    action.Label,
		ActionIdx: actionIdx,
	}

	if action.Type == fix.ActionEdit {
		editPath := action.FilePath
		if editPath == "" {
			editPath = finding.Metadata["compose_path"]
		}
		if editPath != "" {
			checkpointDir := filepath.Join(CheckpointDir, cp.ID)
			// Best-effort checkpoint creation; the fix still applies
			// even if the checkpoint directory can't be created.
			_ = os.MkdirAll(checkpointDir, 0700)
			_ = os.MkdirAll(filepath.Join(checkpointDir, BackupSubdir), 0700)
			if backup, err := BackupFile(checkpointDir, editPath); err == nil {
				cp.Backups = append(cp.Backups, *backup)
			}
		}
	}

	result := f.Run(fix.Context{Finding: finding, Log: func(string, ...interface{}) {}}, actionIdx)

	if result.Success && len(cp.Backups) > 0 {
		cp.Diff = result.Diff
		_ = SaveCheckpoint(cp) // best-effort; fix already applied
	}

	return result
}
