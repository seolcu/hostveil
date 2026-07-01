package history

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

// TestEnsureDirs_OwnerOnlyPermissions is a regression test: checkpoints and
// scan records can contain file diffs or full Snapshot data with secrets
// (e.g. an .env's contents referenced by a compose.dr004 finding, or a
// hardcoded password sitting in the unified-diff context lines around an
// unrelated fix). If BaseDir/CheckpointDir/ScanDir were ever world-readable,
// any local user could read that content regardless of the individual
// file's own permissions.
func TestEnsureDirs_OwnerOnlyPermissions(t *testing.T) {
	withTempHistoryDirs(t)

	if err := EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}

	for _, dir := range []string{BaseDir, CheckpointDir, ScanDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if perm := info.Mode().Perm(); perm != 0700 {
			t.Errorf("%s permissions = %o, want 0700 (owner-only)", dir, perm)
		}
	}
}

// TestEnsureDirs_TightensExistingLoosePermissions covers upgrading from a
// hostveil version that created these directories with looser (e.g. 0755)
// permissions: os.MkdirAll is a no-op on an already-existing directory, so
// EnsureDirs must explicitly os.Chmod to self-heal on the next run.
func TestEnsureDirs_TightensExistingLoosePermissions(t *testing.T) {
	withTempHistoryDirs(t)

	if err := os.MkdirAll(BaseDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(CheckpointDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ScanDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}

	for _, dir := range []string{BaseDir, CheckpointDir, ScanDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if perm := info.Mode().Perm(); perm != 0700 {
			t.Errorf("%s permissions = %o after EnsureDirs, want 0700 (should self-heal from 0755)", dir, perm)
		}
	}
}

// TestSaveCheckpoint_MetaFileOwnerOnly is a regression test: meta.json
// embeds Checkpoint.Diff, a unified diff of the edited file. That diff can
// carry secrets sitting near an unrelated change, so the file must never
// be world- or group-readable.
func TestSaveCheckpoint_MetaFileOwnerOnly(t *testing.T) {
	withTempHistoryDirs(t)

	cp := Checkpoint{ID: "20260101-000000-deadbeef", FindingID: "test.finding", Diff: "--- a/f\n+++ b/f\n-PASSWORD=secret\n+PASSWORD=REDACTED\n"}
	if err := SaveCheckpoint(cp); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	metaPath := filepath.Join(CheckpointDir, cp.ID, "meta.json")
	info, err := os.Stat(metaPath)
	if err != nil {
		t.Fatalf("stat %s: %v", metaPath, err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("meta.json permissions = %o, want 0600 (owner-only)", perm)
	}
}

// TestSaveScan_FileOwnerOnly is a regression test: a saved scan record
// embeds the full Snapshot (every finding, description, and evidence
// map) — a host audit report that must not be world-readable.
func TestSaveScan_FileOwnerOnly(t *testing.T) {
	withTempHistoryDirs(t)

	if err := SaveScan(domain.Snapshot{}); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}

	entries, err := os.ReadDir(ScanDir)
	if err != nil {
		t.Fatalf("ReadDir(ScanDir): %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	info, err := os.Stat(filepath.Join(ScanDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("scan record permissions = %o, want 0600 (owner-only)", perm)
	}
}
