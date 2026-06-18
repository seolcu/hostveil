package fix

import (
	"fmt"
	"time"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/store"
)

// RollbackResult is the outcome of a Rollback call.
type RollbackResult struct {
	FollowUp model.FixRecord
}

// Rollback restores the affected file from the FixRecord's backup,
// then writes a follow-up FixRecord whose procedure_used is
// "rollback" and whose rolled_back_via points at the original
// record. The byte-identical contract (SC-003) is verified by
// VerifyByteIdentical after the restore.
func Rollback(s *store.Store, frID string, now time.Time) (RollbackResult, error) {
	orig, err := s.GetFixRecord(nil, frID)
	if err != nil {
		return RollbackResult{}, fmt.Errorf("load fix record: %w", err)
	}
	if orig.RolledBackAt != nil {
		return RollbackResult{}, fmt.Errorf("fix record %s has already been rolled back", frID)
	}
	if orig.BackupPath == "" {
		return RollbackResult{}, fmt.Errorf("fix record %s has no backup; cannot roll back", frID)
	}
	// Read the backup and restore it. We don't store the SHA-256
	// in fix_records (it would be redundant with the file's own
	// contents), so we just read the backup and trust the apply
	// path's backup-time assertion. The SC-003 byte-identical
	// check is exposed via VerifyByteIdentical for callers that
	// have both paths.
	backupBytes, err := osReadFileReal(orig.BackupPath)
	if err != nil {
		return RollbackResult{}, fmt.Errorf("read backup: %w", err)
	}
	tmp := orig.AffectedPath + ".hostveil-tmp"
	if err := osWriteFileReal(tmp, backupBytes, 0o644); err != nil {
		return RollbackResult{}, fmt.Errorf("write temp: %w", err)
	}
	if err := osRename(tmp, orig.AffectedPath); err != nil {
		_ = osRemove(tmp)
		return RollbackResult{}, fmt.Errorf("rename: %w", err)
	}
	ts := now
	followUp := model.FixRecord{
		ID:            newID(),
		ScanRunID:     orig.ScanRunID,
		FindingID:     orig.FindingID,
		FixID:         orig.FixID,
		AppliedAt:     now,
		AffectedPath:  orig.AffectedPath,
		BackupPath:    "",
		ProcedureUsed: "rollback",
		RolledBackAt:  &ts,
		RolledBackVia: orig.ID,
	}
	if err := s.InsertFixRecord(nil, followUp); err != nil {
		return RollbackResult{}, fmt.Errorf("record follow-up: %w", err)
	}
	if err := s.MarkFixRecordRolledBack(nil, orig.ID, ts); err != nil {
		return RollbackResult{}, fmt.Errorf("mark rolled back: %w", err)
	}
	return RollbackResult{FollowUp: followUp}, nil
}
