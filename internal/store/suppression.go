//go:build linux

package store

import (
	"context"
	"errors"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// ErrSuppressed is returned by AddSuppression when a row for the
// same (host_id, rule_id) already exists; the suppression list
// uses (host_id, rule_id) as a composite primary key.
var ErrSuppressed = errors.New("rule is already suppressed for this host")

// AddSuppression records a suppression row. The reason is free-text
// and may be empty. The created_at timestamp is set to the current
// UTC time; v3.0.0 does not accept a custom timestamp.
func (s *Store) AddSuppression(ctx context.Context, hostID, ruleID, reason string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO suppressions(host_id, rule_id, reason, created_at)
VALUES (?, ?, ?, ?)`,
		hostID, ruleID, reason, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		// SQLite reports a UNIQUE-constraint violation when the
		// row already exists. The error string is the simplest
		// portable way to detect that class of failure; if the
		// driver ever changes we'll swap to a typed error.
		// The string check matches both modernc.org/sqlite's
		// UNIQUE constraint name and the generic message.
		if isUniqueViolation(err) {
			return ErrSuppressed
		}
		return err
	}
	return nil
}

// RemoveSuppression deletes a row by (host_id, rule_id). Returns
// nil when the row didn't exist.
func (s *Store) RemoveSuppression(ctx context.Context, hostID, ruleID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM suppressions WHERE host_id = ? AND rule_id = ?`,
		hostID, ruleID,
	)
	return err
}

// IsSuppressed returns true when a suppression row exists for the
// (host_id, rule_id) pair.
func (s *Store) IsSuppressed(ctx context.Context, hostID, ruleID string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM suppressions WHERE host_id = ? AND rule_id = ?`,
		hostID, ruleID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListSuppressions returns all suppression rows for the given
// host. Used by `hostveil suppress --list`.
func (s *Store) ListSuppressions(ctx context.Context, hostID string) ([]model.Suppression, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT host_id, rule_id, COALESCE(reason, ''), created_at
FROM suppressions
WHERE host_id = ?
ORDER BY created_at DESC`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Suppression
	for rows.Next() {
		var s model.Suppression
		if err := rows.Scan(&s.HostID, &s.RuleID, &s.Reason, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// LoadSuppressionSet returns the set of rule_ids suppressed for
// the given host, in O(1) lookup form. Used by the orchestrator
// to re-label findings on every scan.
func (s *Store) LoadSuppressionSet(ctx context.Context, hostID string) (map[string]bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT rule_id FROM suppressions WHERE host_id = ?`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, err
		}
		out[ruleID] = true
	}
	return out, rows.Err()
}

// isUniqueViolation returns true when the error is a SQLite UNIQUE
// constraint violation. SQLite's error message is the portable
// signal; the typed-error path is driver-specific.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "UNIQUE constraint failed")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
