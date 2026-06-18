//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// InsertFixRecord persists a FixRecord. The store fills in
// JSON-encoded lists and timestamps in RFC 3339.
//
// NOTE: the fix_records.affected_path column is NOT NULL in the
// v3.0.0 schema, so we substitute an empty string for the nil case.
// The CLI and the report layer treat empty as "no specific file".
func (s *Store) InsertFixRecord(ctx context.Context, r model.FixRecord) error {
	if ctx == nil {
		ctx = context.Background()
	}
	rr, _ := encodeJSON(r.RequiresRestart)
	affected := r.AffectedPath
	if affected == "" {
		affected = "(none)"
	}
	backup := r.BackupPath
	_, err := s.db.ExecContext(ctx, `
INSERT INTO fix_records(id, scan_run_id, finding_id, fix_id,
    applied_at, affected_path, backup_path, procedure_used,
    requires_restart_json, restart_deferred, recommended_by,
    rolled_back_at, rolled_back_via)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.ScanRunID, r.FindingID, r.FixID,
		r.AppliedAt.UTC().Format(time.RFC3339),
		affected, backup,
		r.ProcedureUsed, string(rr),
		boolToInt(r.RestartDeferred), nullString(r.RecommendedBy),
		nullTime(r.RolledBackAt), nullString(r.RolledBackVia),
	)
	return err
}

// GetFixRecord returns the FixRecord by id, or ErrNotFound.
func (s *Store) GetFixRecord(ctx context.Context, id string) (model.FixRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var r model.FixRecord
	var appliedAt string
	var rolledBackAt, recommendedBy, rolledBackVia sql.NullString
	var rrJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT id, scan_run_id, finding_id, fix_id, applied_at,
    affected_path, backup_path, procedure_used,
    requires_restart_json, restart_deferred, recommended_by,
    rolled_back_at, rolled_back_via
FROM fix_records WHERE id = ?`, id).Scan(
		&r.ID, &r.ScanRunID, &r.FindingID, &r.FixID, &appliedAt,
		&r.AffectedPath, &r.BackupPath, &r.ProcedureUsed,
		&rrJSON, &r.RestartDeferred, &recommendedBy,
		&rolledBackAt, &rolledBackVia,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.FixRecord{}, ErrNotFound
	}
	if err != nil {
		return model.FixRecord{}, err
	}
	if t, err := time.Parse(time.RFC3339, appliedAt); err == nil {
		r.AppliedAt = t
	}
	if rolledBackAt.Valid {
		if t, err := time.Parse(time.RFC3339, rolledBackAt.String); err == nil {
			r.RolledBackAt = &t
		}
	}
	if recommendedBy.Valid {
		r.RecommendedBy = recommendedBy.String
	}
	if rolledBackVia.Valid {
		r.RolledBackVia = rolledBackVia.String
	}
	if len(rrJSON) > 0 {
		_ = decodeJSON(rrJSON, &r.RequiresRestart)
	}
	return r, nil
}

// MarkFixRecordRolledBack records that the given fix record was
// rolled back at the given time.
func (s *Store) MarkFixRecordRolledBack(ctx context.Context, id string, at time.Time) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE fix_records SET rolled_back_at = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339), id,
	)
	return err
}

// helpers
func encodeJSON(v any) ([]byte, error) {
	return jsonMarshalCompat(v)
}

func decodeJSON(s string, v any) error {
	return jsonUnmarshalCompat([]byte(s), v)
}

func decodeJSONCompat(s string, v any) error {
	return jsonUnmarshalCompat([]byte(s), v)
}
