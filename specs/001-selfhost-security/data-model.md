# Data Model: Hostveil v3.0.0

**Phase**: 1 (Design & Contracts)
**Date**: 2026-06-18
**Spec**: [spec.md](./spec.md)
**Plan**: [plan.md](./plan.md)
**Research**: [research.md](./research.md)

This document refines the entities in spec §"Key Entities" into
concrete Go struct shapes, field types, validation rules, and
relationships. It is the source of truth for `internal/model/*` and
for the SQLite schema in `contracts/state-db.md`.

Conventions used throughout:

- All identifiers are stable strings (UUIDs for runtime objects,
  lowercase-kebab for category / check identifiers).
- All timestamps are RFC 3339 UTC strings in the JSON contract; the
  Go layer uses `time.Time` and serializes via the standard
  `encoding/json` RFC 3339 codec.
- All enum-like fields use typed string constants (Go `type X
  string`) so a typo in the producer is a compile error.

---

## Entity: Host

A single Linux machine. One per `ScanRun` in v3.0.0.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID (string) | Stable per host, derived from `(hostname, machine-id)`; regenerated if either changes. | Non-empty. |
| `hostname` | string | `os.Hostname()` at scan time. | Non-empty. |
| `os_family` | enum | `debian`, `rhel`, `arch`, `alpine`, `other`. | Detected by `internal/platform/packagemanager`. |
| `os_version` | string | `os-release` `VERSION_ID` (best effort). | May be empty on minimal images. |
| `kernel` | string | `uname -r` output. | Non-empty. |
| `arch` | enum | `amd64`, `arm64`, `386`, `armv7`. | Detected at startup. |
| `first_seen_at` | RFC 3339 UTC | First time Hostveil scanned this host. | Read-only after insert. |
| `last_seen_at` | RFC 3339 UTC | Most recent scan start time. | Updated on each scan. |

Relationships: `Host` has many `Service`, `ConfigFile`,
`ContainerImage`, `ScanRun`, `Finding`, `FixRecord`.

State: none — `Host` is an aggregate root, not a state machine.

---

## Entity: Service

A long-running process the host exposes, such as the SSH server, the
Docker daemon, or a named application the program knows how to
classify (Ollama, Jellyfin, NextCloud, Minecraft server, nginx,
caddy).

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per (Host, Service). | Non-empty. |
| `host_id` | UUID (FK) | Owning host. | Non-empty. |
| `name` | string | Canonical name: `sshd`, `docker`, `nginx`, `caddy`, `ollama`, `jellyfin`, `nextcloud`, `minecraft`, etc. | One of the known names; unknown services are recorded as `name="other:<argv0>"`. |
| `status` | enum | `running`, `stopped`, `not-installed`. | Detected per check. |
| `config_file_ids` | []UUID (FK) | Config files that govern this service. | May be empty if the service is config-less. |
| `discovered_at` | RFC 3339 UTC | When the service was first seen on this host. | Read-only after insert. |

Relationships: `Service` belongs to `Host`; references
`ConfigFile` by id.

State: `not-installed` is terminal for a given service. `running`
and `stopped` reflect the last scan's observation.

---

## Entity: ConfigFile

A file on disk the program inspects, such as `/etc/ssh/sshd_config`
or a `docker-compose.yml`.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per (Host, path, content hash). | Non-empty. |
| `host_id` | UUID (FK) | Owning host. | Non-empty. |
| `path` | string | Absolute path on the host. | Non-empty. |
| `owner` | string | `user:group` of the file. | Best effort. |
| `format` | enum | `sshd_config`, `docker_compose_yaml`, `nginx_conf`, `caddyfile`, `sysctl_conf`, `package_manager_list`, `other`. | Detected by parser. |
| `settings` | []Setting | Parsed key/value pairs. | May be empty. |
| `last_seen_at` | RFC 3339 UTC | When the file was last read by a scan. | Updated on each scan. |
| `content_hash` | string | SHA-256 of the file at `last_seen_at`. | Non-empty; used to detect host-side edits between scans. |

Relationships: belongs to `Host`; has many `Setting`; has many
`Finding` that target it.

State: none. Replaced (by id) when the path or content changes
between scans.

---

## Entity: Setting

A single key/value pair inside a `ConfigFile`.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per (ConfigFile, line, key). | Non-empty. |
| `config_file_id` | UUID (FK) | Owning config file. | Non-empty. |
| `line` | int | 1-indexed line number in the file. | >= 1. |
| `key` | string | Parsed key (e.g. `PermitRootLogin`). | Non-empty. |
| `raw_value` | string | The value as it appears in the file, including comments. | Non-empty. |
| `effective_value` | string | The value the program considers effective after applying includes / overrides (for SSH Match blocks, for example). | Non-empty. |
| `safe_value` | string \| null | The value the program considers safe; `null` if no opinion. | None. |

State: none. Re-read on each scan.

---

## Entity: ContainerImage

A Docker image in use on the host.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per (Host, repo:tag@digest). | Non-empty. |
| `host_id` | UUID (FK) | Owning host. | Non-empty. |
| `repository` | string | e.g. `docker.io/library/nginx`. | Non-empty. |
| `tag` | string | e.g. `1.27.3`. | Non-empty; `latest` is a valid but flagged value. |
| `digest` | string | `sha256:...` of the resolved image. | Non-empty when available. |
| `in_use` | bool | Whether a container is currently running from this image on the host. | Updated on each scan. |
| `vulnerability_ids` | []UUID (FK) | CVEs that match this image. | May be empty. |

Relationships: belongs to `Host`; references `Vulnerability` by id.

State: none. `in_use` is refreshed on each scan.

---

## Entity: Vulnerability

A known CVE.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | string | The CVE id, e.g. `CVE-2024-12345`. | Matches `^CVE-\d{4}-\d{4,}$`. |
| `severity` | enum | `low`, `medium`, `high`, `critical`. | One of the four. |
| `cvss_v3_score` | float \| null | CVSS v3 base score, when available. | 0.0 - 10.0. |
| `summary` | string | One-sentence description. | Non-empty. |
| `published_at` | RFC 3339 UTC | NVD / OSV publication date. | Non-empty. |
| `affected_package_ecosystem` | string \| null | e.g. `docker`, `apk`, `deb`. | None. |
| `affected_package_name` | string \| null | The package name within that ecosystem. | None. |
| `affected_version_range` | string \| null | SemVer-ish range. | None. |

Relationships: has many `ContainerImage` via
`ContainerImage.vulnerability_ids`.

State: none in v3.0.0. CVE rows are upserted on each opt-in refresh;
rows whose `affected_*` no longer match any image remain in the
cache for audit but are not surfaced as findings.

---

## Entity: Finding

A single problem the program reports. Central entity.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per Finding. | Non-empty. |
| `scan_run_id` | UUID (FK) | The scan that produced this finding. | Non-empty. |
| `fingerprint` | string | Stable hash of `(category, rule_id, entity_refs)` used to track "new / still present / resolved" across runs (FR-008). | SHA-256 hex; non-empty. |
| `category` | enum | `ssh`, `docker`, `image_cve`, `reverse_proxy`, `ssl_tls`, `hardening_firewall`, `hardening_fail2ban`, `hardening_unattended`, `hardening_sysctl`, `hardening_updates`. | One of the listed values. |
| `rule_id` | string | Stable identifier for the rule that produced the finding, e.g. `ssh.permit_root_login.allow`. | `^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`. |
| `severity` | enum | `low`, `medium`, `high`, `critical`. | One of the four. |
| `title` | string | Plain-language title. | <= 80 chars. |
| `description` | string | Plain-language description with what / why / how. | <= 2000 chars. |
| `entity_refs` | []EntityRef | What the finding points at (Host, Service, ConfigFile, Setting, ContainerImage, Vulnerability). | At least one. |
| `fix_id` | UUID \| null | The built-in fix, if one exists. | None. |
| `state` | enum | `new`, `still_present`, `resolved`, `suppressed`. | Derived per scan. |
| `first_seen_at` | RFC 3339 UTC | When this fingerprint first appeared. | Read-only after insert. |
| `last_seen_at` | RFC 3339 UTC | When this fingerprint was most recently observed. | Updated on each scan. |

Relationships: belongs to `ScanRun`; references `Fix` (optional) by
id; references any number of other entities via `EntityRef`.

State transitions:

```
            new scan, no record   new scan, record exists, still matching
            ──────────────────►  ───────────────────────────────►
            (Fingerprint is new)  (Fingerprint already seen; entity
                                    unchanged; finding re-emitted as
                                    `still_present`)

  new ─► still_present ─► resolved   (host changed, fingerprint no
                                       longer matches any entity)
  still_present ─► resolved
  still_present ─► still_present
  new ─► resolved                    (host was already healthy at
                                       next scan)
  any ─► suppressed                  (user suppressed by rule)
```

`suppressed` is a v3.0.0 user-driven state set via the CLI
(`hostveil suppress <fingerprint>`); the suppression list is stored
in `state.db`.

---

## Entity: EntityRef

A typed reference from a `Finding` to a target entity. Polymorphic
discriminator via `kind`.

| Field | Type | Description | Validation |
|---|---|---|---|
| `kind` | enum | `host`, `service`, `config_file`, `setting`, `container_image`, `vulnerability`. | One of the listed values. |
| `id` | string | The target entity's id. | Non-empty. |
| `display` | string | Human-readable summary for the report (e.g. `/etc/ssh/sshd_config:34`). | Non-empty; <= 200 chars. |

---

## Entity: Fix

A remediation the program can apply for a `Finding`. One-to-one
relationship with a `Finding` in v3.0.0 (a finding either has a
built-in fix or it does not; multi-fix composition is post-v3.0).

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per (rule_id, version). | Non-empty. |
| `rule_id` | string | The `Finding.rule_id` this fix addresses. | Non-empty. |
| `description` | string | Plain-language description of what the fix does. | <= 500 chars. |
| `preview` | string | Human-readable preview of the change. | Non-empty. |
| `procedure` | string | A `hostveil fix` internal command identifier (e.g. `ssh.permit_root_login.set_no`). | Non-empty. |
| `requires_restart` | []string | Service names that must be restarted for the fix to take effect. | May be empty. |
| `requires_elevation` | bool | Whether the fix's procedure needs root. | True for SSH, sysctl, package manager; False for in-place config edits in the user's home. |
| `rollback_supported` | bool | Whether the fix has a rollback procedure. | True when a backup can be taken; False for image-pull fixes. |

Relationships: zero-or-one per `Finding`.

State: `Fix` is a static catalog entry; no state machine.

---

## Entity: FixRecord

A persistent record of a `Fix` that has been applied.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per applied fix. | Non-empty. |
| `scan_run_id` | UUID (FK) | The scan run during which the fix was applied. | Non-empty. |
| `finding_id` | UUID (FK) | The finding that triggered the fix. | Non-empty. |
| `fix_id` | UUID (FK) | The fix that was applied. | Non-empty. |
| `applied_at` | RFC 3339 UTC | When the fix was applied. | Non-empty. |
| `affected_path` | string | The file or resource the fix modified. | Non-empty. |
| `backup_path` | string \| null | The backup location, if the fix supports rollback. | Required iff `Fix.rollback_supported` is true. |
| `procedure_used` | string | The internal command actually run (may differ from the catalog `procedure` if the fix adapted to the host). | Non-empty. |
| `requires_restart` | []string | Copy of the fix's restart list at apply time. | May be empty. |
| `restart_deferred` | bool | True if the user opted to skip the restart at apply time. | False unless explicitly set. |
| `rolled_back_at` | RFC 3339 UTC \| null | Set when the fix is rolled back. | None. |
| `rolled_back_via` | string \| null | The FixRecord id of the rollback entry, if the rollback itself produced a record. | None. |

Relationships: belongs to `ScanRun`; references `Finding`, `Fix`.
Self-referential via `rolled_back_via`.

State: `pending` → `applied` → (`rolled_back` | `re_applied`).
The `pending` state exists for the brief window between
`preview` and user confirmation; in v3.0.0 the apply and the
record are written in the same transaction, so the persisted
state is effectively always `applied` or `rolled_back`.

---

## Entity: ScanRun

A single execution of the scan.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per run. | Non-empty. |
| `host_id` | UUID (FK) | The host scanned. | Non-empty. |
| `started_at` | RFC 3339 UTC | When the scan started. | Non-empty. |
| `finished_at` | RFC 3339 UTC \| null | When the scan finished (success or error). | None until completion. |
| `status` | enum | `running`, `success`, `partial`, `error`. | `running` only between `started_at` and `finished_at`. |
| `categories_scanned` | []Category | Categories that produced a result. | Each value from the `Finding.category` enum. |
| `categories_skipped` | []CategorySkip | Categories that did not run, with reason. | May be empty. |
| `finding_count_by_severity` | map[enum]int | `low`, `medium`, `high`, `critical` → count. | All four keys present; zero allowed. |
| `version` | string | The `hostveil` version that produced this run (semver). | Matches `^v?MAJOR\.MINOR\.PATCH$`. |
| `cve_feed_refreshed` | bool | Whether the CVE cache was refreshed during this run. | True only when `--refresh-cve` was used and the refresh succeeded. |
| `cve_feed_refresh_skipped_reason` | string \| null | Why the CVE refresh was skipped if it was requested. | None. |
| `report_path` | string | Absolute path of the on-disk text report. | Non-empty after success. |
| `hostveil_exit_code` | int | The exit code the run would have produced. | 0/1/2. |

Relationships: belongs to `Host`; has many `Finding`, `FixRecord`.

State: `running` → (`success` | `partial` | `error`). `partial`
means some categories succeeded and some were skipped due to
elevation failure or missing prerequisites.

---

## Entity: CategorySkip

Why a category was skipped during a scan run.

| Field | Type | Description | Validation |
|---|---|---|---|
| `category` | Category | Which category was skipped. | Non-empty. |
| `reason` | enum | `not_applicable`, `missing_prerequisite`, `elevation_denied`, `headless_no_tty`, `unsupported_platform`, `internal_error`. | One of the listed values. |
| `detail` | string | Human-readable detail (e.g. "user is not in the sudo group"). | <= 500 chars. |

---

## Identity, uniqueness, and lifecycle summary

- **Stable identity**:
  - `Host` is identified by `(hostname, machine-id)`.
  - `Service` is identified by `(host_id, name)`.
  - `ConfigFile` is identified by `(host_id, path, content_hash)`;
    the same path with a different content_hash is a new `ConfigFile`
    (we keep the previous record for diffing, but the new id is the
    "current" one).
  - `ContainerImage` is identified by `(host_id, repo, tag, digest)`.
  - `Vulnerability` is identified by its `CVE-*` id.
  - `Finding` is identified by `fingerprint` (a hash of
    `(category, rule_id, sorted(entity_refs))`). The same
    fingerprint across runs means "same problem on the same
    artifact".
  - `Fix` is identified by `(rule_id, version)`.
  - `FixRecord` and `ScanRun` are append-only and identified by
    UUID.

- **Lifecycle**:
  - Append-only: `ScanRun`, `Finding`, `FixRecord`, `Vulnerability`.
  - Upsert by stable key: `Host`, `Service`, `ConfigFile`,
    `ContainerImage`, `Fix`.
  - Read-only after insert: nothing else; everything is replaced
    or appended, never mutated in place.

This shape is the input to the SQLite schema in
`contracts/state-db.md`.

---

## Entity: TUISession

A single `hostveil tui` invocation. Append-only.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per session. | Non-empty. |
| `host_id` | UUID (FK) | The host the session was opened against. | Non-empty. |
| `started_at` | RFC 3339 UTC | When the session opened. | Non-empty. |
| `ended_at` | RFC 3339 UTC \| null | When the session closed. | NULL while running. |
| `exit_reason` | enum | `user-quit`, `no-tty`, `internal-error`, `killed`. | NULL while running. |
| `findings_expanded` | int | Count of "explain" actions the user took. | >= 0. |
| `fix_actions_triggered` | int | Count of "apply fix" actions the user triggered. | >= 0. |
| `terminal_cols` | int | Terminal width at session start. | > 0. |
| `terminal_rows` | int | Terminal height at session start. | > 0. |
| `color_enabled` | bool | Whether the session used ANSI color. | Detected at start. |

Relationships: belongs to `Host`.

State: `running` → `closed`. Closed sessions are never reopened.

---

## Entity: WebSession

A single `hostveil web` invocation. Append-only.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per session. | Non-empty. |
| `host_id` | UUID (FK) | The host the dashboard is bound to. | Non-empty. |
| `started_at` | RFC 3339 UTC | When the server started listening. | Non-empty. |
| `ended_at` | RFC 3339 UTC \| null | When the server stopped. | NULL while running. |
| `bind_address` | string | The address the server bound to (e.g. `127.0.0.1:34567`). | Non-empty. |
| `is_loopback` | bool | Whether the bind address is loopback. | True for `127.0.0.1` or `::1`; false otherwise. |
| `auth_token_sha256` | string \| null | SHA-256 of the auth token the user must present. NULL when `is_loopback` is true and no token was generated. | Required iff `is_loopback` is false. |
| `tls_fingerprint` | string \| null | SHA-256 of the TLS certificate served (DER form). NULL when the bind is loopback and plain HTTP is used. | None. |
| `dashboard_views` | int | Count of GET requests to the dashboard root. | >= 0. |
| `fix_actions_triggered` | int | Count of POST requests to the fix endpoint. | >= 0. |
| `rejected_auth_attempts` | int | Count of requests that failed the auth check. | >= 0. |

Relationships: belongs to `Host`.

State: `running` → `closed`. The `auth_token` itself is **never**
persisted; only its SHA-256 is. The token is regenerated on every
restart of the `web` subcommand.

---

## Entity: AIProvider

The configuration of a single AI provider. One row per
configured provider. The set of configured providers is
populated by the user (config file or env vars); v3.0.0 ships
with a default `ollama` entry that points at
`http://localhost:11434` and no `anthropic` entry unless the user
sets `ANTHROPIC_API_KEY`.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per provider row. | Non-empty. |
| `name` | string | Display name (`ollama-local`, `anthropic-prod`). | Non-empty; unique per host. |
| `kind` | enum | `ollama`, `anthropic`, `custom`. | One of the three. |
| `base_url` | string | The provider's API base URL. | Non-empty; HTTPS for cloud, HTTP allowed for `127.0.0.1`/`localhost`. |
| `model` | string | The model identifier the provider should be called with. | Non-empty. |
| `api_key_ref` | string \| null | Reference to the API key source: `env:ANTHROPIC_API_KEY` or `config:anthropic.api_key`. Never the key itself. | NULL for local providers. |
| `privacy_tier` | enum | `local`, `cloud-self-hosted`, `cloud-vendor`. | One of the three; `local` is set automatically for `ollama` on loopback. |
| `consent_required` | bool | Whether the user must give one-time consent before the first cloud call. | True for any `cloud-*` tier; false for `local`. |
| `consent_recorded_at` | RFC 3339 UTC \| null | When the user last gave consent. | Required iff `consent_required` and a call has been made. |
| `enabled` | bool | Whether the provider is available to the AI layer. | True by default; false disables the provider without deleting its config. |

Relationships: has many `AIRequest`.

State: configuration rows are updated on `hostveil ai configure`;
the `consent_recorded_at` field is the only state-like field.

---

## Entity: AIRequest

A single AI call. Append-only. Used for audit and for the
per-call rate-limit state.

| Field | Type | Description | Validation |
|---|---|---|---|
| `id` | UUID | Stable per request. | Non-empty. |
| `ai_provider_id` | UUID (FK) | The provider used. | Non-empty. |
| `host_id` | UUID (FK) | The host on whose behalf the call was made. | Non-empty. |
| `requested_at` | RFC 3339 UTC | When the call was started. | Non-empty. |
| `method` | enum | `explain`, `risk`, `recommend`. | One of the three. |
| `model` | string | The model that actually served the call. | Non-empty. |
| `redacted_prompt_sha256` | string | SHA-256 of the redacted prompt (the prompt itself is NOT persisted; only the hash, for audit). | Non-empty. |
| `response_text` | string \| null | The model's response, when successful. | NULL on failure. |
| `failure_class` | enum \| null | `unreachable`, `timeout`, `rate-limit`, `malformed`, `prompt-injection-suspected`, `consent-denied`, `auth-failed`, `other`. | NULL on success. |
| `tokens_in` | int \| null | Reported by the provider when available. | NULL when not reported. |
| `tokens_out` | int \| null | Reported by the provider when available. | NULL when not reported. |
| `latency_ms` | int | Wall-clock latency of the call. | > 0. |
| `latency_budget_ms` | int | The latency budget the caller allowed (e.g. 30000 for `explain`). | > 0. |
| `tui_session_id` | UUID (FK, optional) | TUI session that triggered the call, when applicable. | NULL. |
| `web_session_id` | UUID (FK, optional) | Web session that triggered the call, when applicable. | NULL. |

Relationships: belongs to `AIProvider`, `Host`; optionally belongs
to a `TuiSession` or `WebSession`.

State: append-only. Used by the rate-limit window (60 seconds
sliding window) to enforce FR-033.

---

## Identity, uniqueness, and lifecycle summary (updated)
