//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

// migrations is the ordered list of schema migrations. Each entry is
// applied in version order; applying is idempotent via the
// schema_migrations table.
var migrations = []migration{
	{
		version: 1,
		name:    "0001_initial",
		sql: `
CREATE TABLE hosts (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    os_family TEXT NOT NULL,
    os_version TEXT,
    kernel TEXT NOT NULL,
    arch TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_hosts_hostname_machine_id ON hosts(hostname, machine_id);

CREATE TABLE services (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    discovered_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_services_host_name ON services(host_id, name);
CREATE INDEX idx_services_host ON services(host_id);

CREATE TABLE config_files (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    path TEXT NOT NULL,
    owner_user TEXT,
    owner_group TEXT,
    format TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_config_files_host_path_hash ON config_files(host_id, path, content_hash);
CREATE INDEX idx_config_files_host_path ON config_files(host_id, path);

CREATE TABLE settings (
    id TEXT PRIMARY KEY,
    config_file_id TEXT NOT NULL REFERENCES config_files(id) ON DELETE CASCADE,
    line INTEGER NOT NULL,
    key TEXT NOT NULL,
    raw_value TEXT NOT NULL,
    effective_value TEXT NOT NULL,
    safe_value TEXT
);
CREATE UNIQUE INDEX idx_settings_file_line_key ON settings(config_file_id, line, key);
CREATE INDEX idx_settings_file ON settings(config_file_id);

CREATE TABLE container_images (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    digest TEXT NOT NULL,
    in_use INTEGER NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_images_host_repo_tag_digest ON container_images(host_id, repository, tag, digest);
CREATE INDEX idx_images_host_in_use ON container_images(host_id, in_use);

CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    cvss_v3_score REAL,
    summary TEXT NOT NULL,
    published_at TEXT NOT NULL,
    affected_package_ecosystem TEXT,
    affected_package_name TEXT,
    affected_version_range TEXT,
    fetched_at TEXT NOT NULL
);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);

CREATE TABLE container_image_vulnerabilities (
    container_image_id TEXT NOT NULL REFERENCES container_images(id) ON DELETE CASCADE,
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    PRIMARY KEY (container_image_id, vulnerability_id)
);

CREATE TABLE scan_runs (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    categories_scanned_json TEXT NOT NULL,
    categories_skipped_json TEXT NOT NULL,
    finding_count_critical INTEGER NOT NULL,
    finding_count_high INTEGER NOT NULL,
    finding_count_medium INTEGER NOT NULL,
    finding_count_low INTEGER NOT NULL,
    hostveil_version TEXT NOT NULL,
    cve_feed_refreshed INTEGER NOT NULL,
    cve_feed_refresh_skipped_reason TEXT,
    report_path TEXT,
    hostveil_exit_code INTEGER NOT NULL
);
CREATE INDEX idx_scan_runs_host_started ON scan_runs(host_id, started_at DESC);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    category TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    entity_refs_json TEXT NOT NULL,
    fix_id TEXT REFERENCES fixes(id),
    state TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_scan_run ON findings(scan_run_id);
CREATE INDEX idx_findings_state ON findings(state);

CREATE TABLE fixes (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT NOT NULL,
    preview TEXT NOT NULL,
    procedure TEXT NOT NULL,
    requires_restart_json TEXT NOT NULL,
    requires_elevation INTEGER NOT NULL,
    rollback_supported INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_fixes_rule_version ON fixes(rule_id, version);
CREATE INDEX idx_fixes_rule ON fixes(rule_id);

CREATE TABLE fix_records (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    fix_id TEXT NOT NULL REFERENCES fixes(id),
    applied_at TEXT NOT NULL,
    affected_path TEXT NOT NULL,
    backup_path TEXT,
    procedure_used TEXT NOT NULL,
    requires_restart_json TEXT NOT NULL,
    restart_deferred INTEGER NOT NULL,
    recommended_by TEXT,
    rolled_back_at TEXT,
    rolled_back_via TEXT
);
CREATE INDEX idx_fix_records_scan ON fix_records(scan_run_id);
CREATE INDEX idx_fix_records_finding ON fix_records(finding_id);

CREATE TABLE suppressions (
    host_id TEXT NOT NULL REFERENCES hosts(id),
    rule_id TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (host_id, rule_id)
);

CREATE TABLE cve_cache_meta (
    id INTEGER PRIMARY KEY,
    last_refreshed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    next_refresh_after TEXT NOT NULL
);

CREATE TABLE tui_sessions (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    started_at TEXT NOT NULL,
    ended_at TEXT,
    exit_reason TEXT,
    findings_expanded INTEGER NOT NULL,
    fix_actions_triggered INTEGER NOT NULL,
    terminal_cols INTEGER NOT NULL,
    terminal_rows INTEGER NOT NULL,
    color_enabled INTEGER NOT NULL
);
CREATE INDEX idx_tui_sessions_host_started ON tui_sessions(host_id, started_at DESC);

CREATE TABLE web_sessions (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    started_at TEXT NOT NULL,
    ended_at TEXT,
    bind_address TEXT NOT NULL,
    is_loopback INTEGER NOT NULL,
    auth_token_sha256 TEXT,
    tls_fingerprint TEXT,
    dashboard_views INTEGER NOT NULL,
    fix_actions_triggered INTEGER NOT NULL,
    rejected_auth_attempts INTEGER NOT NULL
);
CREATE INDEX idx_web_sessions_host_started ON web_sessions(host_id, started_at DESC);

CREATE TABLE ai_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    kind TEXT NOT NULL,
    base_url TEXT NOT NULL,
    model TEXT NOT NULL,
    api_key_ref TEXT,
    privacy_tier TEXT NOT NULL,
    consent_required INTEGER NOT NULL,
    consent_recorded_at TEXT,
    enabled INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_ai_providers_host_name ON ai_providers(host_id, name);
CREATE INDEX idx_ai_providers_host_enabled ON ai_providers(host_id, enabled);

CREATE TABLE ai_requests (
    id TEXT PRIMARY KEY,
    ai_provider_id TEXT NOT NULL REFERENCES ai_providers(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    requested_at TEXT NOT NULL,
    method TEXT NOT NULL,
    model TEXT NOT NULL,
    redacted_prompt_sha256 TEXT NOT NULL,
    response_text TEXT,
    failure_class TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    latency_ms INTEGER NOT NULL,
    latency_budget_ms INTEGER NOT NULL,
    tui_session_id TEXT,
    web_session_id TEXT
);
CREATE INDEX idx_ai_requests_host_time ON ai_requests(host_id, requested_at DESC);
CREATE INDEX idx_ai_requests_provider_time ON ai_requests(ai_provider_id, requested_at DESC);
`,
	},
}

type migration struct {
	version int
	name    string
	sql     string
}

// InsertHost upserts a host row keyed on (hostname, machine_id).
// On conflict, last_seen_at and the OS fields are refreshed.
func (s *Store) InsertHost(ctx context.Context, h model.Host) error {
	const q = `
INSERT INTO hosts(id, hostname, machine_id, os_family, os_version, kernel, arch, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(hostname, machine_id) DO UPDATE SET
    os_family=excluded.os_family,
    os_version=excluded.os_version,
    kernel=excluded.kernel,
    arch=excluded.arch,
    last_seen_at=excluded.last_seen_at
`
	_, err := s.db.ExecContext(ctx, q,
		h.ID, h.Hostname, "", h.OSFamily, nullString(h.OSVersion), h.Kernel, h.Arch,
		h.FirstSeenAt.UTC().Format(time.RFC3339), h.LastSeenAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert host: %w", err)
	}
	return nil
}

// GetHost returns the host row by id, or ErrNotFound.
func (s *Store) GetHost(ctx context.Context, id string) (model.Host, error) {
	const q = `SELECT id, hostname, os_family, COALESCE(os_version,''), kernel, arch, first_seen_at, last_seen_at
              FROM hosts WHERE id = ?`
	var h model.Host
	var fs, ls string
	err := s.db.QueryRowContext(ctx, q, id).Scan(
		&h.ID, &h.Hostname, &h.OSFamily, &h.OSVersion, &h.Kernel, &h.Arch, &fs, &ls,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Host{}, ErrNotFound
	}
	if err != nil {
		return model.Host{}, err
	}
	h.FirstSeenAt, _ = time.Parse(time.RFC3339, fs)
	h.LastSeenAt, _ = time.Parse(time.RFC3339, ls)
	return h, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
