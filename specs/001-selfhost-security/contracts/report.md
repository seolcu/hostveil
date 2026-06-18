# Report File Contract: Hostveil v3.0.0

**Phase**: 1 (Design & Contracts)
**Date**: 2026-06-18
**Spec**: [spec.md](../spec.md)
**Plan**: [plan.md](../plan.md)
**Data Model**: [data-model.md](../data-model.md)
**Research**: [research.md](../research.md)

This document locks the on-disk and stdout report format for
Hostveil v3.0.0. Two surfaces are defined:

1. **Text report** — the default. Rendered from the same data as
   the JSON, ≤ 120 columns wide (SC-005), no ANSI codes when
   written to a file (ANSI allowed on stdout when `--color=always`
   is set).
2. **JSON report** — available via `--format=json` on `scan`,
   `fix`, and `rollback`. The schema is the canonical
   machine-readable form; the text is rendered from it.

Both surfaces are produced from the same in-memory representation
so the two never disagree. The JSON shape is locked by
`tests/contract/report_json_test.go`; the text format is locked by
`tests/contract/report_text_test.go`.

---

## File path

`<--report-dir>/hostveil-YYYYMMDD-HHMMSS.txt`

- `<--report-dir>` defaults to
  `~/.local/share/hostveil/reports/`.
- The directory is created on first run if it does not exist
  (no elevation needed; user's home).
- Filename suffix is `.txt` for text reports and `.json` for
  `--format=json` reports.
- `--no-report-file` suppresses file output entirely (stdout only).

---

## Text report shape

A text report has five sections in this order:

1. **Header** — scan metadata.
2. **Summary** — finding counts and run status.
3. **Findings** — one block per finding, grouped by category,
   ordered by severity within each category.
4. **Skipped categories** — categories that did not run, with
   reason.
5. **Footer** — exit code explanation and pointers.

Each section is delimited by a blank line. No section is omitted
(empty sections are still emitted as a one-line placeholder
followed by a blank line) so consumers can rely on section
boundaries.

### 1. Header

```
Hostveil v3.0.0 (commit a1b2c3d4, built 2026-06-18T10:00:00Z)
Host:     homelab (Linux debian 6.1.0-13-amd64, amd64)
Scan:     2026-06-18T10:00:00Z → 2026-06-18T10:00:42Z (42s)
Status:   partial (5 of 6 categories scanned)
Report:   /home/alice/.local/share/hostveil/reports/hostveil-20260618-100000.txt
```

Fields are left-padded so the colons align. The duration is
formatted as `<seconds>s` for < 60 s, `<m>m<seconds>s` for
< 60 min, else `<h>h<m>m`.

### 2. Summary

```
Summary
-------
  critical:  0
  high:      2
  medium:    5
  low:       3
  total:    10

  new since last run:        4
  still present:             6
  resolved since last run:   1
  suppressed:                0
```

The "new / still / resolved / suppressed" counts add up to `total`
minus any findings skipped at the producer side (e.g. findings in
a category that errored mid-run are not counted here; they are
listed in section 4 instead).

### 3. Findings

Findings are grouped by `Finding.category`. The category header
is one of the locked enum values, displayed in title case
(`SSH`, `Docker`, `Image CVEs`, `Reverse Proxy`, `SSL/TLS`,
`Hardening — Firewall`, `Hardening — Fail2ban`, `Hardening —
Unattended Upgrades`, `Hardening — Sysctl`, `Hardening — Pending
Updates`).

Within each category, findings are ordered by severity
(`critical` → `high` → `medium` → `low`), then by `rule_id` for
deterministic ordering.

Each finding block:

```
[high] [new] SSH: Root login is allowed over SSH
  /etc/ssh/sshd_config:34  PermitRootLogin yes
  What:  Anyone who can reach your SSH port can try to log in as the
         root user, which bypasses the normal user → sudo flow.
  Why:   If the root password is weak, leaked, or guessed, the attacker
         gets full control of the host with no further escalation.
  Fix:   hostveil fix abc-123-...
         (will set PermitRootLogin to "no"; sshd will be reloaded)
```

Rules:
- The header line is always one line, `<= 120` columns. If the
  title would overflow, it is truncated with an ellipsis.
- The location line is always present when the finding has at
  least one `EntityRef` of kind `config_file` or `setting` or
  `container_image`; otherwise it is omitted.
- The `What` paragraph is mandatory and ≤ 6 lines.
- The `Why` paragraph is mandatory and ≤ 4 lines.
- The `Fix` line is present only when the finding has a built-in
  fix; the line shows the exact command the user would run. If the
  fix requires a service restart, the trailing parenthetical names
  the service.
- Each paragraph is wrapped at ≤ 100 columns with hanging
  indentation of 9 spaces (2 for the `What:` / `Why:` label and
  7 for the column).
- Findings that are `resolved` are listed under a sibling
  `Resolved findings` subsection at the bottom of the report,
  with one line per finding (`[severity] <title> — <entity display>`)
  and a count header. They are not interleaved with active
  findings.

### 4. Skipped categories

```
Skipped categories
------------------
  hardening — firewall   (elevation_denied: user is not in the sudo group)
  reverse proxy          (not_applicable: nginx/caddy not detected)
```

The category is shown in lowercase, the reason in
`snake_case`. `detail` is included when present.

### 5. Footer

```
Exit code
---------
  0  no high or critical findings
  1  at least one high or critical finding was detected
  2  scan errored (this run is `partial` or `error`)

This run is `partial`. Re-run with elevation to scan the skipped
categories, or with `--explain` for plain-language help on each
finding.

Generated by Hostveil v3.0.0. Report any false positives to
<project's issue tracker URL>.
```

The "Re-run with elevation" hint is only printed when
`hardening — firewall` or `hardening — sysctl` (or other elevated
categories) is in the skipped list with reason `elevation_denied`.

---

## JSON report shape

Top-level object:

```json
{
  "$schema": "https://hostveil.dev/schemas/report/v3.json",
  "schema_version": "1.0.0",
  "hostveil_version": "3.0.0",
  "hostveil_commit": "a1b2c3d4",
  "hostveil_built_at": "2026-06-18T10:00:00Z",
  "scan_run": {
    "id": "<uuid>",
    "host_id": "<uuid>",
    "started_at": "2026-06-18T10:00:00Z",
    "finished_at": "2026-06-18T10:00:42Z",
    "duration_seconds": 42,
    "status": "partial",
    "categories_scanned": ["ssh", "docker", "image_cve", "ssl_tls", "hardening_updates"],
    "categories_skipped": [
      {
        "category": "hardening_firewall",
        "reason": "elevation_denied",
        "detail": "user is not in the sudo group"
      }
    ],
    "finding_count_by_severity": {
      "critical": 0, "high": 2, "medium": 5, "low": 3
    },
    "hostveil_exit_code": 1,
    "cve_feed_refreshed": false,
    "report_path": "/home/alice/.local/share/hostveil/reports/hostveil-20260618-100000.txt"
  },
  "host": {
    "id": "<uuid>",
    "hostname": "homelab",
    "os_family": "debian",
    "os_version": "12",
    "kernel": "6.1.0-13-amd64",
    "arch": "amd64"
  },
  "findings": [
    {
      "id": "<uuid>",
      "fingerprint": "<sha256-hex>",
      "category": "ssh",
      "rule_id": "ssh.permit_root_login.allow",
      "severity": "high",
      "state": "new",
      "title": "Root login is allowed over SSH",
      "description": "PermitRootLogin is set to \"yes\"...",
      "entity_refs": [
        {
          "kind": "config_file",
          "id": "<uuid>",
          "display": "/etc/ssh/sshd_config:34"
        }
      ],
      "fix": {
        "id": "<uuid>",
        "rule_id": "ssh.permit_root_login.allow",
        "description": "Set PermitRootLogin to \"no\" and reload sshd.",
        "requires_restart": ["sshd"],
        "requires_elevation": true,
        "rollback_supported": true
      },
      "first_seen_at": "2026-06-18T10:00:00Z",
      "last_seen_at": "2026-06-18T10:00:00Z"
    }
  ]
}
```

### Locked rules

- All field names are `snake_case`.
- All enum fields use the same string values as the data model
  (e.g. `category: "hardening_firewall"`, never `"hardening/firewall"`).
- All timestamps are RFC 3339 UTC with `Z` suffix.
- `findings` is sorted by `(category, severity, rule_id)` to match
  the text report ordering.
- `entity_refs` within a finding is sorted by `(kind, id)`.
- Unknown fields are not allowed; the JSON decoder is strict.
- The top-level `$schema` and `schema_version` fields are
  mandatory and are the contract version, not the hostveil
  version. A hostveil v3.0.0 release that changes the report
  shape in a backward-incompatible way MUST bump
  `schema_version`.

### Redaction

The producer (`internal/report`) applies redaction before
serialization. The following patterns are replaced with `[REDACTED]`
in any string field that could carry them:

- PEM private-key blocks (`-----BEGIN ... PRIVATE KEY-----` ... `-----END ... PRIVATE KEY-----`).
- Values of keys named `password`, `passwd`, `secret`, `api_key`,
  `token`, `bearer`, `private_key` in any parsed config file.
- Anything matching `https?://[^:@\s]+:[^@\s]+@` (credentials in
  URLs).
- Anything matching the AWS access-key pattern
  `AKIA[0-9A-Z]{16}`.

The redaction list is a contract: it is locked by
`tests/contract/report_json_test.go`. Adding a new pattern is a
minor version bump of `schema_version`.

---

## Relationship to the SQLite state database

The report is a *projection* of the `ScanRun`, `Finding`, and
`FixRecord` rows in `state.db` for the run that produced it. The
JSON `scan_run.id` matches the `ScanRun.id` row exactly. The
report is never a source of truth — the database is. The report
can be regenerated from the database at any time using
`hostveil report <scan-run-id>` (post-v3.0; v3.0.0 only writes
the report at scan time).
