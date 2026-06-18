package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

func newTempStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func nowish() time.Time {
	return time.Date(2026, 6, 18, 0, 0, 0, 0, time.UTC)
}

func TestOpen_Pragmas(t *testing.T) {
	s := newTempStore(t)

	var journalMode string
	if err := s.db.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want wal", journalMode)
	}

	var fk int
	if err := s.db.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}
}

func TestOpen_ForeignKeyEnforcement(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	// Inserting a service for a non-existent host must fail with
	// FOREIGN KEY constraint, not silently succeed.
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO services(id, host_id, name, status, discovered_at) VALUES (?, ?, ?, ?, ?)",
		"svc-1", "host-does-not-exist", "sshd", "running", "2026-06-18T00:00:00Z",
	)
	if err == nil {
		t.Errorf("expected FOREIGN KEY violation when inserting a service with a missing host_id, got nil")
	}
}

func TestMigrate_AppliesAndIsIdempotent(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	// Apply already happened on Open; running again must be a no-op.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() second call error = %v", err)
	}

	// schema_migrations should have at least one row.
	row := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations")
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatalf("SELECT COUNT(*) from schema_migrations: %v", err)
	}
	if n < 1 {
		t.Errorf("schema_migrations has %d rows, want >= 1", n)
	}

	// The spec's required tables must exist.
	required := []string{
		"hosts", "services", "config_files", "settings", "container_images",
		"vulnerabilities", "container_image_vulnerabilities", "scan_runs",
		"findings", "fixes", "fix_records", "suppressions", "cve_cache_meta",
		"tui_sessions", "web_sessions", "ai_providers", "ai_requests",
	}
	for _, table := range required {
		row := s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table)
		var c int
		if err := row.Scan(&c); err != nil {
			t.Fatalf("checking table %s: %v", table, err)
		}
		if c != 1 {
			t.Errorf("table %s missing after migration", table)
		}
	}
}

func TestStore_InsertAndReadHost(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	host := model.Host{
		ID: "host-1", Hostname: "testbox", OSFamily: "debian", OSVersion: "12",
		Kernel: "6.1.0", Arch: "amd64", FirstSeenAt: nowish(), LastSeenAt: nowish(),
	}
	if err := s.InsertHost(ctx, host); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	got, err := s.GetHost(ctx, "host-1")
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if got.Hostname != "testbox" || got.OSFamily != "debian" {
		t.Errorf("GetHost returned %+v", got)
	}
}
