# Public CLI Contract: Hostveil v3.0.0

**Phase**: 1 (Design & Contracts)
**Date**: 2026-06-18
**Spec**: [spec.md](../spec.md)
**Plan**: [plan.md](../plan.md)
**Data Model**: [data-model.md](../data-model.md)
**Research**: [research.md](../research.md)

This document is the locked public CLI surface for Hostveil v3.0.0.
It is enforced by `tests/contract/cli_test.go`; any change to a
command name, flag, positional argument, default value, or exit code
is a breaking change and requires a `CHANGELOG.md` entry (Constitution
Principle V).

Conventions:

- All flags use kebab-case (`--cve-source`, not `--cveSource`).
- All subcommand names are lowercase verbs or verb-nouns (`scan`,
  `fix`, `rollback`, `explain`, `version`).
- `--format=json` is supported on `scan`, `fix`, and `rollback`;
  text is the default.
- Exit codes:
  - `0` — success, no high-severity or critical finding.
  - `1` — success, at least one high-severity or critical finding
    was detected.
  - `2` — scan errored (a category failed internally and the
    orchestrator could not produce a complete result).

---

## `hostveil`

Top-level command. With no subcommand, prints short help and exits
with code `0`.

```
hostveil [global flags] <subcommand> [subcommand flags] [args]
```

### Global flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--config` | path | `~/.config/hostveil/config.toml` | Path to the user config file. |
| `--log-level` | enum | `info` | One of `debug`, `info`, `warn`, `error`. |
| `--log-file` | path \| empty | empty | If set, structured logs are also written to this file (JSON). |
| `--no-color` | bool | false | Disable ANSI color in the text report. |
| `--color` | enum | `auto` | `auto`, `always`, `never`. |

---

## `hostveil scan`

Runs a full or partial scan and writes a report.

```
hostveil scan [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--categories` | csv | all | One or more of `ssh,docker,images,proxy,ssl,hardening`. |
| `--refresh-cve` | bool | false | Force a CVE-feed refresh before scanning image categories. |
| `--cve-source` | enum | `nvd` | `nvd` or `osv`. Ignored unless `--refresh-cve` or the cache is stale and `--refresh-cve` is implied by `--refresh-on-stale`. |
| `--refresh-on-stale` | bool | true | If the CVE cache is older than `--cve-cache-ttl`, refresh transparently. |
| `--cve-cache-ttl` | duration | `24h` | Maximum age of the CVE cache before a refresh is considered. |
| `--refresh-packages` | bool | false | Force a package-metadata refresh. |
| `--report-dir` | path | `~/.local/share/hostveil/reports/` | Where the on-disk report is written. |
| `--no-report-file` | bool | false | Do not write a report file; stdout only. |
| `--format` | enum | `text` | `text` or `json`. |
| `--explain` | bool | false | For each high-severity or critical finding, also emit a plain-language explanation block in the text report. |

### Behavior

1. Resolves the host (hostname + machine-id).
2. Starts a new `ScanRun` and writes it to `state.db` with
   `status=running`.
3. For each requested category:
   - Determines if elevation is required.
   - Batches all elevation needs into a single sudo/pkexec prompt
     at scan start (Spec edge case: "multiple elevation prompts in
     a single scan").
   - Runs the category; on `internal_error`, the category is
     recorded as `CategorySkip` and the run continues.
4. Classifies each `Finding` as `new` / `still_present` /
   `resolved` via the fingerprint table.
5. Renders the report to stdout and (unless `--no-report-file`) to
   `--report-dir/hostveil-YYYYMMDD-HHMMSS.txt`.
6. Marks the `ScanRun` as `success` or `partial` and writes the
   `report_path` back into the row.
7. Exits with `0` (no high/critical) or `1` (at least one
   high/critical).

### Output

- `stdout` — the report (text or JSON).
- `stderr` — structured logs and progress messages.
- Exit code — see top of file.

---

## `hostveil fix`

Applies a built-in fix for a single finding.

```
hostveil fix <finding-id-or-fingerprint> [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--yes` | bool | false | Skip the interactive confirmation; the preview is still printed. |
| `--no-restart` | bool | false | If the fix requires a service restart, do not restart it. Recorded in the `FixRecord` as `restart_deferred=true`. |
| `--no-backup` | bool | false | Skip the backup step. Not allowed for fixes whose `Fix.rollback_supported` is true unless `--force` is also set. |
| `--force` | bool | false | Acknowledge risky behavior (e.g. skipping a backup for a fix that supports rollback). |
| `--format` | enum | `text` | `text` or `json`. |

### Behavior

1. Looks up the finding by id or fingerprint from the most recent
   `ScanRun`.
2. If the finding has no built-in fix, exits with code `2` and a
   clear error message.
3. Prints the preview of the change (FR-005: human-readable
   preview).
4. If `--yes` is not set, prompts the user for explicit
   confirmation. On decline, exits `0` without changes.
5. Snapshots the affected file or resource to a backup path under
   `~/.local/share/hostveil/backups/`.
6. Applies the fix via the elevated sub-process (FR-018: minimum
   command, scoped elevation, no retained privileges).
7. Writes a `FixRecord` (FR-006).
8. If the fix requires a service restart and `--no-restart` is not
   set, prompts to restart. On decline, sets
   `restart_deferred=true` on the record.
9. Re-runs the relevant category (locally, no new scan run) and
   prints a one-line confirmation that the finding is now resolved.
10. Exits `0` on success, `1` on user-cancelled restart that left
    the fix applied but pending restart, `2` on internal error.

### Output

- `stdout` — preview + result (text or JSON).
- `stderr` — structured logs and confirmation prompts.
- Exit code — see step 10.

---

## `hostveil rollback`

Rolls back a previously applied fix.

```
hostveil rollback <fix-record-id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--yes` | bool | false | Skip the interactive confirmation. |
| `--format` | enum | `text` | `text` or `json`. |

### Behavior

1. Looks up the `FixRecord` by id. Refuses (exit `2`) if the record
   is already rolled back.
2. Refuses (exit `2`) if `FixRecord.backup_path` is null. The user
   is told to consult the v3.0.0 release notes for fixes that do
   not support rollback.
3. Prints a preview of the rollback: the path that will be
   restored and the size of the file that will be replaced.
4. If `--yes` is not set, prompts for confirmation.
5. Restores the file from the backup (FR-007: byte-identical
   content, verified by SHA-256 of the backup vs. the
   pre-rollback state — SC-003).
6. Writes a follow-up `FixRecord` with `procedure_used=rollback`
   and `rolled_back_via=<original id>`.
7. Exits `0` on success, `2` on error.

### Output

- `stdout` — preview + result (text or JSON).
- `stderr` — structured logs and prompts.
- Exit code — see step 7.

---

## `hostveil explain`

Explains a finding (or a `rule_id` if no specific finding is given)
in plain language. This is the spec's "explain any finding in plain
language" requirement (FR-010).

```
hostveil explain <finding-id-or-fingerprint-or-rule-id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | enum | `text` | `text` or `json`. |

### Behavior

1. Looks up the finding / rule by id.
2. Prints a structured explanation:
   - **What is happening**: a one-sentence summary.
   - **Why it matters**: the realistic risk in non-technical terms.
   - **What the fix changes**: a description of the change and
     what functionality might be affected.
   - **How to verify**: a one-liner the user can run to confirm
     the fix.
3. Exits `0` on success, `2` on unknown id.

### Output

- `stdout` — the explanation.
- `stderr` — structured logs only.
- Exit code — see step 3.

---

## `hostveil suppress`

Suppresses a finding's `rule_id` so it is not reported on future
scans. v3.0.0 supports a per-host suppression list; per-rule
opt-outs and global suppression are post-v3.0.

```
hostveil suppress <rule-id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--reason` | string | empty | Free-text reason, recorded in the suppression row. |
| `--list` | bool | false | List current suppressions; positional `<rule-id>` is optional in this mode. |

### Behavior

1. Validates that `<rule-id>` matches the `Finding.rule_id` regex.
2. Writes a suppression row keyed by `(host_id, rule_id)`.
3. On the next `hostveil scan`, any finding whose `fingerprint`
   hashes to a suppressed `rule_id` is recorded as
   `state=suppressed` and is not included in the human report's
   high/critical count.
4. Exits `0` on success, `2` on invalid id.

### Output

- `stdout` — confirmation (or suppression list if `--list`).
- Exit code — see step 4.

---

## `hostveil version`

Prints the version, git commit, and build date embedded in the
binary. Used by `--version` global flag and by the contract tests
that lock the version shape.

```
hostveil version [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | enum | `text` | `text` or `json`. |

### Behavior

- Prints: `hostveil v3.0.0 (commit <sha>, built <RFC3339>)`.
- Exits `0`.

---

## `hostveil tui`

Starts the interactive Terminal UI (Spec FR-021..FR-023, full
contract in `contracts/tui.md`). Stub when built with `notui`
tag.

```
hostveil tui [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--host-id` | UUID \| empty | most recent | Which host's findings to show. |
| `--category` | csv \| empty | all | Filter to one or more categories. |
| `--severity` | csv \| empty | all | Filter to one or more severities. |
| `--no-color` | bool | auto-detect | Disable ANSI styling. |
| `--ai` | bool | false | Enable the "AI explain" action. |

### Behavior

1. Verify stdin and stdout are TTYs (FR-022); otherwise print
   a one-line message and exit `0`.
2. Open a `TUISession` row, render the dashboard.
3. Drive the bubbletea model through the keyboard protocol in
   `contracts/tui.md`.
4. On `q` / `Ctrl+C`, close the `TUISession` row with
   `exit_reason=user-quit` and exit `0`.

---

## `hostveil web`

Starts a local web server (Spec FR-024..FR-027, full contract in
`contracts/web.md`). Stub when built with `noweb` tag.

```
hostveil web [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--bind` | addr | `127.0.0.1:0` | Loopback bind with a random port. Non-loopback requires `--auth-token` and TLS. |
| `--auth-token` | string \| empty | random UUIDv4 | Required when binding to a non-loopback address. |
| `--tls-cert` | path \| empty | auto-generated | TLS certificate (required for non-loopback). |
| `--tls-key` | path \| empty | required with `--tls-cert` | TLS private key. |
| `--read-only` | bool | false | Disable the "apply fix" action. |

### Behavior

1. Validates flags (non-loopback bind requires auth + TLS).
2. Generates a session token, opens a `WebSession` row, starts
   the HTTP server.
3. Prints the URL, the auth token (if any), and the TLS
   fingerprint (if any) to stdout.
4. Blocks until SIGINT/SIGTERM, then closes the `WebSession` row.
5. Exits `0` on clean shutdown, `2` on startup error.

See `contracts/web.md` for the full HTTP API and the error
contract.

---

## `hostveil ai <method>`

Invokes an AI provider (Spec FR-028..FR-033, full contract in
`contracts/ai.md`). Stub when built with `noai` tag.

```
hostveil ai explain   <finding-id> [flags]
hostveil ai risk      <finding-id> [flags]
hostveil ai recommend <finding-id> [flags]
hostveil ai configure [flags]
hostveil ai list      [flags]
```

### Flags (shared)

| Flag | Type | Default | Description |
|---|---|---|---|
| `--provider` | string | `ollama-local` | Provider name (from `hostveil ai list`). |
| `--format` | enum | `text` | `text` or `json`. |
| `--timeout` | duration | `30s` | Max wait for the provider. |

### Behavior

1. Resolves the finding from the most recent `ScanRun`.
2. Resolves the provider; for cloud providers, runs the
   one-time consent flow on first call.
3. Sends a redacted prompt (see `contracts/ai.md`).
4. On success, prints the response (text or JSON).
5. On any failure, prints the static explanation with a
   one-line warning and exits `0` (per FR-033).
6. Exits `2` only for configuration errors (unknown provider,
   missing API key, finding id not found).

---

## Error and edge-case behavior (cross-cutting)

| Situation | Behavior |
|---|---|
| Unsupported platform (non-Linux) | Print `unsupported platform: <GOOS>` to stderr; exit `2`. |
| Headless / no TTY when elevation is required | Skip elevated categories with reason `headless_no_tty`; print a clear message; exit `1` if any high/critical finding was found in the non-elevated categories, else `0`. |
| Elevation prompt denied | Skip affected categories with reason `elevation_denied`; continue. |
| Report directory does not exist | Create it on first run (no elevation needed; user's home). |
| Report file write fails | Print the report to stdout, emit a warning naming the reason; do not fail the run. |
| Stale `--config` file | Print a warning, fall back to defaults; exit `0`/`1` per finding result, not `2`. |
| Concurrent `hostveil` invocations on the same user | Serialize at the SQLite level (busy timeout 5 s); if the lock cannot be acquired, exit `2` with a clear message. |
