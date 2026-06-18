//go:build linux

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// InsertScanRun writes a new scan_runs row. The categories_scanned
// and categories_skipped slices are JSON-encoded into the *_json
// columns per contracts/state-db.md.
func (s *Store) InsertScanRun(ctx context.Context, r *model.ScanRun) error {
	sc, _ := json.Marshal(r.CategoriesScanned)
	sk, _ := json.Marshal(r.CategoriesSkipped)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO scan_runs(id, host_id, started_at, finished_at, status,
    categories_scanned_json, categories_skipped_json,
    finding_count_critical, finding_count_high, finding_count_medium, finding_count_low,
    hostveil_version, cve_feed_refreshed, cve_feed_refresh_skipped_reason,
    report_path, hostveil_exit_code)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.HostID, r.StartedAt.UTC().Format(time.RFC3339),
		nullTime(r.FinishedAt), r.Status, string(sc), string(sk),
		r.FindingCountCritical, r.FindingCountHigh, r.FindingCountMedium, r.FindingCountLow,
		r.HostveilVersion, boolToInt(r.CVEFEEDRefreshed), nullString(r.CVEFEEDRefreshSkipped),
		nullString(r.ReportPath), r.HostveilExitCode,
	)
	return err
}

// UpdateScanRun rewrites the mutable columns of a scan_runs row.
func (s *Store) UpdateScanRun(ctx context.Context, r *model.ScanRun) error {
	sc, _ := json.Marshal(r.CategoriesScanned)
	sk, _ := json.Marshal(r.CategoriesSkipped)
	_, err := s.db.ExecContext(ctx, `
UPDATE scan_runs SET finished_at=?, status=?,
    categories_scanned_json=?, categories_skipped_json=?,
    finding_count_critical=?, finding_count_high=?, finding_count_medium=?, finding_count_low=?,
    report_path=?, hostveil_exit_code=?
WHERE id=?`,
		nullTime(r.FinishedAt), r.Status, string(sc), string(sk),
		r.FindingCountCritical, r.FindingCountHigh, r.FindingCountMedium, r.FindingCountLow,
		nullString(r.ReportPath), r.HostveilExitCode, r.ID,
	)
	return err
}

// UpdateReportPath records the on-disk path of the report file for
// the given scan run. Used after the report layer writes the file.
func (s *Store) UpdateReportPath(ctx context.Context, scanRunID, path string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs SET report_path=? WHERE id=?`, path, scanRunID,
	)
	return err
}

// InsertFindings bulk-inserts the findings of a single ScanRun.
func (s *Store) InsertFindings(ctx context.Context, scanRunID string, findings []model.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO findings(id, scan_run_id, fingerprint, category, rule_id,
    severity, title, description, entity_refs_json, fix_id, state,
    first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range findings {
		refs, _ := json.Marshal(f.EntityRefs)
		fixID := nullString(f.FixID)
		_, err := stmt.ExecContext(ctx,
			f.ID, scanRunID, f.Fingerprint, f.Category, f.RuleID,
			f.Severity, f.Title, f.Description, string(refs), fixID, f.State,
			f.FirstSeenAt.UTC().Format(time.RFC3339), f.LastSeenAt.UTC().Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.ID, err)
		}
	}
	return tx.Commit()
}

// PreviousFingerprints returns the set of fingerprints observed on
// previous runs against this host, mapped to the first time each
// was seen. The orchestrator uses this to label findings as
// new / still_present / resolved.
func (s *Store) PreviousFingerprints(ctx context.Context, hostID string) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT f.fingerprint, MIN(f.first_seen_at)
FROM findings f
JOIN scan_runs r ON r.id = f.scan_run_id
WHERE r.host_id = ?
GROUP BY f.fingerprint
HAVING MAX(f.last_seen_at) < (
    SELECT MAX(started_at) FROM scan_runs WHERE host_id = ? AND status IN ('success','partial')
)
`, hostID, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var fp, fs string
		if err := rows.Scan(&fp, &fs); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339, fs)
		out[fp] = t
	}
	return out, rows.Err()
}

// HostIDFor returns the host row id for the given fingerprint, or
// ErrNotFound when no host has been recorded yet.
func (s *Store) HostIDFor(ctx context.Context, fp string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM hosts WHERE id = ?`, fp).Scan(&id)
	if err != nil {
		return "", ErrNotFound
	}
	return id, nil
}

// InsertHostByID writes a host row using a pre-computed id (the
// sha256 of hostname|machine-id per scan.hostID).
func (s *Store) InsertHostByID(ctx context.Context, h model.Host) error {
	const q = `INSERT OR REPLACE INTO hosts(id, hostname, machine_id, os_family, os_version, kernel, arch, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, q,
		h.ID, h.Hostname, "", h.OSFamily, nullString(h.OSVersion), h.Kernel, h.Arch,
		h.FirstSeenAt.UTC().Format(time.RFC3339), h.LastSeenAt.UTC().Format(time.RFC3339),
	)
	return err
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
