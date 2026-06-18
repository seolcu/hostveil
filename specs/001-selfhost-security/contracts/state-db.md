# State Database Contract: Hostveil v3.0.0

**Phase**: 1 (Design & Contracts)
**Date**: 2026-06-18
**Spec**: [spec.md](../spec.md)
**Plan**: [plan.md](../plan.md)
**Data Model**: [data-model.md](../data-model.md)
**Research**: [research.md](../research.md)

This document locks the SQLite schema that backs Hostveil v3.0.0's
scan history, finding fingerprints, fix records, and CVE cache.
The on-disk file lives at `~/.local/share/hostveil/state.db`
(XDG data home). Migrations are forward-only and tracked in the
`schema_migrations` table; rollback is not supported in v3.0.0.

The schema is the source of truth for what Hostveil knows about
the host. Reports are projections of this state; deleting a row
here is the supported way to "forget" a finding or a fix.

---

## Global settings

- **Journal mode**: `WAL` (concurrent readers, single writer).
- **Foreign keys**: `ON`.
- **Busy timeout**: 5 seconds (matches the CLI error contract for
  concurrent invocations).
- **Default `synchronous`**: `NORMAL` (safe with WAL, faster than
  `FULL`).
- **Encoding**: UTF-8.

The connection layer (`internal/store`) is responsible for
applying these pragmas on every new connection.

---

## `schema_migrations`

Tracks applied migrations. Inserted by the migrator on each
successful apply; never modified after that.

| column | type | notes |
|---|---|---|
| `version` | INTEGER PRIMARY KEY | Monotonically increasing migration id. |
| `name` | TEXT NOT NULL | Human-readable migration name. |
| `applied_at` | TEXT NOT NULL | RFC 3339 UTC timestamp. |

The first migration is `1`. Each migration is a single SQL
transaction applied in order; the migrator refuses to start if
any migration in the chain is missing.

---

## `hosts`

One row per `(hostname, machine-id)`. See `Host` in the data
model.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `hostname` | TEXT NOT NULL | `os.Hostname()` at first scan. |
| `machine_id` | TEXT NOT NULL | `/etc/machine-id` content (or `/var/lib/dbus/machine-id` fallback). |
| `os_family` | TEXT NOT NULL | `debian`, `rhel`, `arch`, `alpine`, `other`. |
| `os_version` | TEXT | May be NULL. |
| `kernel` | TEXT NOT NULL | `uname -r` at first scan. |
| `arch` | TEXT NOT NULL | `amd64`, `arm64`, `386`, `armv7`. |
| `first_seen_at` | TEXT NOT NULL | RFC 3339 UTC. |
| `last_seen_at` | TEXT NOT NULL | RFC 3339 UTC. |

Unique index: `(hostname, machine_id)`.

---

## `services`

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `name` | TEXT NOT NULL | Canonical name; see data model. |
| `status` | TEXT NOT NULL | `running`, `stopped`, `not-installed`. |
| `discovered_at` | TEXT NOT NULL | RFC 3339 UTC. |

Unique index: `(host_id, name)`.
Index: `(host_id)`.

---

## `config_files`

A new row per `(host_id, path, content_hash)`. Same path with a
different `content_hash` is a new row; the previous row is
retained for diffing but is not the "current" row.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `path` | TEXT NOT NULL | Absolute path. |
| `owner_user` | TEXT | May be NULL if stat failed. |
| `owner_group` | TEXT | May be NULL if stat failed. |
| `format` | TEXT NOT NULL | See data model enum. |
| `content_hash` | TEXT NOT NULL | SHA-256 hex. |
| `last_seen_at` | TEXT NOT NULL | RFC 3339 UTC. |

Unique index: `(host_id, path, content_hash)`.
Index: `(host_id, path)` for "current row for this path"
lookups.

---

## `settings`

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `config_file_id` | TEXT NOT NULL | FK → `config_files.id` (ON DELETE CASCADE). |
| `line` | INTEGER NOT NULL | 1-indexed. |
| `key` | TEXT NOT NULL | |
| `raw_value` | TEXT NOT NULL | |
| `effective_value` | TEXT NOT NULL | |
| `safe_value` | TEXT | NULL when no opinion. |

Unique index: `(config_file_id, line, key)`.
Index: `(config_file_id)`.

---

## `container_images`

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `repository` | TEXT NOT NULL | |
| `tag` | TEXT NOT NULL | |
| `digest` | TEXT NOT NULL | `sha256:...`. |
| `in_use` | INTEGER NOT NULL | 0 / 1; updated on each scan. |
| `last_seen_at` | TEXT NOT NULL | RFC 3339 UTC. |

Unique index: `(host_id, repository, tag, digest)`.
Index: `(host_id, in_use)` for "what is currently running".

---

## `vulnerabilities`

CVE rows. Upserted on each `--refresh-cve`; rows that no longer
match any image are retained for audit.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | `CVE-YYYY-NNNN`. |
| `severity` | TEXT NOT NULL | `low`, `medium`, `high`, `critical`. |
| `cvss_v3_score` | REAL | NULL when unavailable. |
| `summary` | TEXT NOT NULL | |
| `published_at` | TEXT NOT NULL | RFC 3339 UTC. |
| `affected_package_ecosystem` | TEXT | NULL when not applicable. |
| `affected_package_name` | TEXT | NULL when not applicable. |
| `affected_version_range` | TEXT | NULL when not applicable. |
| `fetched_at` | TEXT NOT NULL | When the row was last refreshed. |

Index: `(severity)`.

---

## `container_image_vulnerabilities`

Many-to-many join. Recomputed on each scan; rows for images that
no longer match are removed at the end of the run.

| column | type | notes |
|---|---|---|
| `container_image_id` | TEXT NOT NULL | FK → `container_images.id` (ON DELETE CASCADE). |
| `vulnerability_id` | TEXT NOT NULL | FK → `vulnerabilities.id` (ON DELETE CASCADE). |

PRIMARY KEY: `(container_image_id, vulnerability_id)`.

---

## `scan_runs`

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `started_at` | TEXT NOT NULL | RFC 3339 UTC. |
| `finished_at` | TEXT | NULL while `status='running'`. |
| `status` | TEXT NOT NULL | `running`, `success`, `partial`, `error`. |
| `categories_scanned_json` | TEXT NOT NULL | JSON array of category strings. |
| `categories_skipped_json` | TEXT NOT NULL | JSON array of `CategorySkip` objects. |
| `finding_count_critical` | INTEGER NOT NULL | |
| `finding_count_high` | INTEGER NOT NULL | |
| `finding_count_medium` | INTEGER NOT NULL | |
| `finding_count_low` | INTEGER NOT NULL | |
| `hostveil_version` | TEXT NOT NULL | SemVer. |
| `cve_feed_refreshed` | INTEGER NOT NULL | 0 / 1. |
| `cve_feed_refresh_skipped_reason` | TEXT | NULL when not applicable. |
| `report_path` | TEXT | NULL until the report is written. |
| `hostveil_exit_code` | INTEGER | The exit code the run would have produced. |

Index: `(host_id, started_at DESC)` for "most recent run for this
host".

The JSON columns are encoded with the stdlib `encoding/json` and
match the shapes in `report.md`. The schema is intentionally
"wide" on the four severity counts to keep report rendering a
single SELECT.

---

## `findings`

Findings are append-only across runs; the same `fingerprint` may
appear in many rows. The fingerprint is the join key for the
"new / still / resolved" logic.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `scan_run_id` | TEXT NOT NULL | FK → `scan_runs.id` (ON DELETE CASCADE). |
| `fingerprint` | TEXT NOT NULL | SHA-256 hex; see data model. |
| `category` | TEXT NOT NULL | Enum; see data model. |
| `rule_id` | TEXT NOT NULL | |
| `severity` | TEXT NOT NULL | Enum. |
| `title` | TEXT NOT NULL | |
| `description` | TEXT NOT NULL | |
| `entity_refs_json` | TEXT NOT NULL | JSON array of `EntityRef`. |
| `fix_id` | TEXT | FK → `fixes.id`; NULL when no built-in fix. |
| `state` | TEXT NOT NULL | `new`, `still_present`, `resolved`, `suppressed`. |
| `first_seen_at` | TEXT NOT NULL | |
| `last_seen_at` | TEXT NOT NULL | |

Indexes:
- `(fingerprint)` — for "is this fingerprint new?".
- `(scan_run_id)` — for "what did this run find?".
- `(host_id, fingerprint, last_seen_at DESC)` — via a join with
  `scan_runs`; the planner uses the `scan_runs(host_id,
  started_at DESC)` index and the `findings(fingerprint)` index.

`host_id` is not a column on `findings`; the join to `scan_runs`
is always required. The "host_id" pseudo-index above is the
planner's plan, not a real index.

---

## `fixes`

Static catalog; one row per `(rule_id, version)`. Seeded by the
binary on first run; updated by migrations.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `rule_id` | TEXT NOT NULL | |
| `version` | TEXT NOT NULL | SemVer of the fix definition. |
| `description` | TEXT NOT NULL | |
| `preview` | TEXT NOT NULL | |
| `procedure` | TEXT NOT NULL | Internal command identifier. |
| `requires_restart_json` | TEXT NOT NULL | JSON array of strings. |
| `requires_elevation` | INTEGER NOT NULL | 0 / 1. |
| `rollback_supported` | INTEGER NOT NULL | 0 / 1. |

Unique index: `(rule_id, version)`.
Index: `(rule_id)`.

---

## `fix_records`

Append-only.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `scan_run_id` | TEXT NOT NULL | FK → `scan_runs.id` (ON DELETE CASCADE). |
| `finding_id` | TEXT NOT NULL | FK → `findings.id` (ON DELETE CASCADE). |
| `fix_id` | TEXT NOT NULL | FK → `fixes.id`. |
| `applied_at` | TEXT NOT NULL | RFC 3339 UTC. |
| `affected_path` | TEXT NOT NULL | |
| `backup_path` | TEXT | NULL when not supported. |
| `procedure_used` | TEXT NOT NULL | |
| `requires_restart_json` | TEXT NOT NULL | |
| `restart_deferred` | INTEGER NOT NULL | 0 / 1. |
| `rolled_back_at` | TEXT | NULL until rolled back. |
| `rolled_back_via` | TEXT | Self-FK to `fix_records.id`; NULL until rolled back. |

Index: `(scan_run_id)`, `(finding_id)`.

---

## `suppressions`

| column | type | notes |
|---|---|---|
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `rule_id` | TEXT NOT NULL | |
| `reason` | TEXT | Free-text. |
| `created_at` | TEXT NOT NULL | RFC 3339 UTC. |

PRIMARY KEY: `(host_id, rule_id)`.

---

## `cve_cache_meta`

Single-row table tracking the last refresh of the CVE cache.

| column | type | notes |
|---|---|---|
| `id` | INTEGER PRIMARY KEY | Always 1. |
| `last_refreshed_at` | TEXT NOT NULL | RFC 3339 UTC. |
| `source` | TEXT NOT NULL | `nvd` or `osv`. |
| `row_count` | INTEGER NOT NULL | |
| `next_refresh_after` | TEXT NOT NULL | When `last_refreshed_at + ttl` is reached. |

---

## `tui_sessions`

Append-only. See `TUISession` in the data model.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `started_at` | TEXT NOT NULL | RFC 3339 UTC. |
| `ended_at` | TEXT | NULL while running. |
| `exit_reason` | TEXT | `user-quit`, `no-tty`, `internal-error`, `killed`; NULL while running. |
| `findings_expanded` | INTEGER NOT NULL | |
| `fix_actions_triggered` | INTEGER NOT NULL | |
| `terminal_cols` | INTEGER NOT NULL | |
| `terminal_rows` | INTEGER NOT NULL | |
| `color_enabled` | INTEGER NOT NULL | 0 / 1. |

Index: `(host_id, started_at DESC)`.

---

## `web_sessions`

Append-only. See `WebSession` in the data model. The auth
**token** is never persisted; only its SHA-256 fingerprint.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `started_at` | TEXT NOT NULL | RFC 3339 UTC. |
| `ended_at` | TEXT | NULL while running. |
| `bind_address` | TEXT NOT NULL | |
| `is_loopback` | INTEGER NOT NULL | 0 / 1. |
| `auth_token_sha256` | TEXT | NULL when `is_loopback` is 1 and no token was needed. |
| `tls_fingerprint` | TEXT | NULL when loopback and plain HTTP. |
| `dashboard_views` | INTEGER NOT NULL | |
| `fix_actions_triggered` | INTEGER NOT NULL | |
| `rejected_auth_attempts` | INTEGER NOT NULL | |

Index: `(host_id, started_at DESC)`.

---

## `ai_providers`

One row per configured provider. See `AIProvider` in the data
model. The API key is **never** stored; only the env-var or
config-key reference.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `name` | TEXT NOT NULL | Display name; unique per host. |
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `kind` | TEXT NOT NULL | `ollama`, `anthropic`, `custom`. |
| `base_url` | TEXT NOT NULL | |
| `model` | TEXT NOT NULL | |
| `api_key_ref` | TEXT | NULL for local providers. |
| `privacy_tier` | TEXT NOT NULL | `local`, `cloud-self-hosted`, `cloud-vendor`. |
| `consent_required` | INTEGER NOT NULL | 0 / 1. |
| `consent_recorded_at` | TEXT | RFC 3339 UTC; NULL until consent. |
| `enabled` | INTEGER NOT NULL | 0 / 1. |

Unique index: `(host_id, name)`.
Index: `(host_id, enabled)`.

---

## `ai_requests`

Append-only audit log. See `AIRequest` in the data model.
The **prompt** is never persisted; only its SHA-256.

| column | type | notes |
|---|---|---|
| `id` | TEXT PRIMARY KEY | UUID. |
| `ai_provider_id` | TEXT NOT NULL | FK → `ai_providers.id` (ON DELETE CASCADE). |
| `host_id` | TEXT NOT NULL | FK → `hosts.id`. |
| `requested_at` | TEXT NOT NULL | RFC 3339 UTC. |
| `method` | TEXT NOT NULL | `explain`, `risk`, `recommend`. |
| `model` | TEXT NOT NULL | |
| `redacted_prompt_sha256` | TEXT NOT NULL | SHA-256 of the redacted prompt. |
| `response_text` | TEXT | NULL on failure. |
| `failure_class` | TEXT | NULL on success. |
| `tokens_in` | INTEGER | NULL when not reported. |
| `tokens_out` | INTEGER | NULL when not reported. |
| `latency_ms` | INTEGER NOT NULL | |
| `latency_budget_ms` | INTEGER NOT NULL | |
| `tui_session_id` | TEXT | FK → `tui_sessions.id`; NULL. |
| `web_session_id` | TEXT | FK → `web_sessions.id`; NULL. |

Index: `(host_id, requested_at DESC)`.
Index: `(ai_provider_id, requested_at DESC)`.

---

## Migration rules

- Migrations are forward-only. There is no `down` migration.
- Each migration is a single `.sql` file under
  `internal/store/migrations/` named `NNNN_name.sql` where
  `NNNN` is the zero-padded version.
- Each migration is wrapped in `BEGIN ... COMMIT`; the
  `schema_migrations` insert is part of the same transaction.
- A migration MAY add new tables, add new columns to existing
  tables, or add new indexes. It MUST NOT drop columns, rename
  columns, or change column types (SQLite is permissive about
  types but the application code is not).
- The migrator refuses to start when the on-disk version is
  newer than what the binary knows about. This catches the
  "user downgraded hostveil" case and exits with a clear error.

---

## Backup and portability

- The database is a single file plus its `-wal` and `-shm`
  siblings while WAL is active. A user-level copy with
  `hostveil db copy <path>` is the supported way to snapshot it
  (post-v3.0; v3.0.0 only ships the live file).
- The database contains no secrets (FR-020). The producer
  redacts before write; there is no other path into the
  database.
- The database is per-user, not per-host. If the same user runs
  Hostveil on multiple hosts (sequentially), each host's `id` is
  different and the rows coexist; `hostveil list-hosts` and
  `hostveil list-runs --host <id>` (post-v3.0) read across them.
