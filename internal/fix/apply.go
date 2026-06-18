package fix

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/store"
)

// ApplyResult is the outcome of an Apply call.
type ApplyResult struct {
	FixRecord model.FixRecord
	Backup    BackupPath
}

// Apply runs the fix for the given finding. The flow is:
//
//  1. Confirm the user has approved (handled by the caller — Apply
//     does not re-prompt).
//  2. Back up the affected file or resource.
//  3. Apply the change.
//  4. Persist a FixRecord (so the user can roll back).
//
// In v3.0.0-alpha, step 3 is a placeholder: the real fix procedures
// land post-v3.0. The backup, record, and rollback paths are fully
// wired and tested.
func Apply(s *store.Store, srID, findID string, f model.Finding, force bool, now time.Time) (ApplyResult, error) {
	// 1) Conflict check.
	if conflicts := Detect(f); len(conflicts) > 0 && !force {
		return ApplyResult{}, fmt.Errorf("conflicts detected (%d) but --force not set: %s",
			len(conflicts), describeConflicts(conflicts))
	}

	// 2) Backup the affected file.
	bp, err := backupAffected(f)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("backup: %w", err)
	}

	// 3) Apply the change. v3.0.0-alpha has no real procedures;
	// we record the fix as "applied" with a procedure tag that
	// signals this. The post-v3.0 catalog will replace this with
	// real per-rule procedures.
	if err := applyChange(f); err != nil {
		return ApplyResult{}, fmt.Errorf("apply: %w", err)
	}

	// 4) Persist the FixRecord.
	rec := model.FixRecord{
		ID:              newID(),
		ScanRunID:       srID,
		FindingID:       findID,
		FixID:           "fix-" + f.RuleID,
		AppliedAt:       now,
		AffectedPath:    primaryPath(f),
		BackupPath:      bp.Full,
		ProcedureUsed:   "v3.0.0-alpha-placeholder",
		RequiresRestart: nil,
		RestartDeferred: false,
	}
	if err := s.InsertFixRecord(nil, rec); err != nil {
		return ApplyResult{}, fmt.Errorf("record: %w", err)
	}
	return ApplyResult{FixRecord: rec, Backup: bp}, nil
}

// backupAffected finds the file the fix is going to change and
// backs it up. In v3.0.0-alpha we back up the first file-type
// entity ref; post-v3.0 the catalog maps each rule to a specific
// path.
func backupAffected(f model.Finding) (BackupPath, error) {
	target := primaryPath(f)
	if target == "" {
		// Nothing to back up (e.g. an image-CVE finding). Return
		// a zero BackupPath; the FixRecord will record an empty
		// affected_path and an empty backup_path.
		return BackupPath{}, nil
	}
	// The base dir is $XDG_DATA_HOME/hostveil/backups/. We resolve
	// it on demand to avoid a hard dependency on the store from
	// the backup code.
	dir, err := defaultBackupsDir()
	if err != nil {
		return BackupPath{}, err
	}
	return CreateBackup(dir, target)
}

// defaultBackupsDir returns the XDG backups directory. Pulled in
// here rather than from the store package so internal/fix has a
// minimum dependency surface.
func defaultBackupsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, ".local", "share", "hostveil", "backups")
	return d, nil
}

// applyChange performs the actual change. v3.0.0-alpha has no real
// procedures; the post-v3.0 catalog will replace this switch with
// the real per-rule implementations. For now we do nothing on disk
// and record a placeholder FixRecord so the user can still test
// the apply / rollback plumbing end to end.
func applyChange(f model.Finding) error {
	_ = f
	return nil
}

// primaryPath returns the on-disk path the fix will affect, or ""
// when the finding has no file-shaped entity.
func primaryPath(f model.Finding) string {
	for _, r := range f.EntityRefs {
		if r.Kind == model.EntityRefKindConfigFile || r.Kind == model.EntityRefKindSetting {
			return r.Display
		}
	}
	return ""
}

// describeConflicts returns a short, human-readable summary of a
// conflict list. The CLI uses this in the error message when the
// user has not passed --force.
func describeConflicts(cs []Conflict) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, fmt.Sprintf("[%s] %s:%d", c.Kind, c.Path, c.Line))
	}
	return joinStrings(parts, "; ")
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// newID returns a short unique id for a FixRecord.
func newID() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("fix-%d", time.Now().UnixNano())))
	return "fr-" + hex.EncodeToString(sum[:8])
}
