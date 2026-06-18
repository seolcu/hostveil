# How hostveil works

This document describes the architecture, the threat model, the
build-time tag matrix, and the privacy posture of hostveil v3.

## Overview

hostveil is a single-binary Linux program that scans a self-hoster's
host for common security misconfigurations across six categories
(SSH, Docker, image CVEs, reverse proxy, SSL/TLS, and system
hardening), presents the findings in plain language, and applies
reversible fixes with a built-in rollback path.

The product targets non-expert self-hosters who run a homelab on
a Linux server. v3 ships three user surfaces — a CLI, an
interactive TUI, and a local web dashboard — plus an opt-in AI
layer for richer explanations. v3.0.0 ships the CLI surface
fully; the TUI, Web, and AI surfaces are stubbed in v3.0.0 and
land in v3.x.

## Architecture

```
              +---------------------------+
              |       cmd/hostveil        |
              |  (main: cobra dispatcher)  |
              +-------------+-------------+
                            |
              +-------------v-------------+
              |       internal/cli         |
              |  scan, fix, rollback,      |
              |  explain, suppress, ...    |
              +-------------+-------------+
                            |
        +-------------------+-------------------+
        |                                       |
+-------v-------+                       +-------v-------+
| internal/scan |                       | internal/fix  |
| orchestrator  |                       | preview,      |
| fingerprint   |                       | backup,       |
| classification|                       | apply,        |
+---------------+                       | rollback,     |
        |                               | conflict      |
        |                               +---------------+
+-------v-------+                               |
| internal/     |                               |
|  checks/      |                               |
|  {category}/  |                               |
|  (6 packages) |                               |
+---------------+                               |
        |                                       |
+-------v---------------------------------------v-------+
|                internal/store                      |
|  SQLite (modernc.org/sqlite, pure Go)              |
|  + migrations + Insert/Update typed accessors      |
+---------------------------------------------------+
        |
+-------v-------+
|  state.db     |
|  ~/.local/    |
|  share/       |
|  hostveil/    |
+---------------+
```

### Package map

| Package | Role |
|---|---|
| `cmd/hostveil` | Entry point; cobra dispatcher, XDG path setup, platform check. |
| `internal/cli` | The 9 subcommands; flag parsing; exit-code mapping (`HitError` → 1). |
| `internal/scan` | The orchestrator; per-category invocation, batched elevation, fingerprint classification (new / still_present / resolved / suppressed), scan-run row lifecycle. |
| `internal/checks/{ssh,docker,images,proxy,ssl,hardening}` | One package per scan category; each exposes a `Run(ctx) (Result, error)` function. |
| `internal/fix` | The apply / preview / backup / apply / rollback / record / conflict flow per FR-005..FR-007, FR-011. |
| `internal/store` | The SQLite state.db; the migrations framework; the typed accessors. |
| `internal/report` | Text + JSON report renderers; the redaction list; the on-disk sink. |
| `internal/model` | The 22 canonical entity types from `data-model.md`. |
| `internal/log` | Structured `log/slog` JSON handler with `component` and `scan_run_id`. |
| `internal/version` | Build-time version / commit / date. |
| `internal/platform/privilege` | `sudo` / `pkexec` batching. |
| `internal/platform/{packagemanager,sysctl,docker}` | Per-distro host adapters. |
| `internal/tui` (v3.x) | bubbletea-based TUI. |
| `internal/web` (v3.x) | localhost web dashboard. |
| `internal/ai` (v3.x) | opt-in AI explanations. |

## Threat model

v3.0.0 assumes the following:

- The user runs hostveil on a host they own or administer, with
  a shell account that can read `/etc/ssh/sshd_config`,
  `/etc/nginx/nginx.conf`, `/etc/caddy/Caddyfile`,
  `/etc/ssl/certs`, etc. via either normal user or sudo.
- The Docker socket (`/var/run/docker.sock`) is readable by the
  user (or root) for the `docker` category.
- The user's home directory is writable, so the program can
  create `~/.local/share/hostveil/`.
- The user's terminal may not be a TTY (CI, headless); the
  TUI subcommand degrades to a one-line message in that case.

v3.0.0 explicitly does **not** defend against:

- A host that the attacker has already compromised before
  hostveil runs. hostveil is not a runtime IDS; it is a
  configuration auditor.
- A host whose `state.db` has been tampered with. The store
  has no integrity check; v3.x adds an HMAC over the scan
  history.
- A network attacker probing the host during a scan. The
  scanner is read-only on local state; it does not open network
  connections except for the optional CVE feed refresh.

## Build-time tag matrix

hostveil ships three build-time tag options. Tags are mutually
compatible and produce smaller, narrower binaries.

| Tag | Excludes | Verifies |
|---|---|---|
| `noai` | All of `internal/ai/`. | The CI gate runs `strings` over the produced binary and fails if `(?i)anthropic|openai|ollama` matches. |
| `notui` | All of `internal/tui/`. | The TUI subcommand prints "built without TUI" and exits 0. |
| `noweb` | All of `internal/web/`. | The web subcommand prints "built without Web UI" and exits 0. |

The default build (no tags) ships the CLI surface fully; the TUI,
Web, and AI surfaces are stubbed. The TUI/Web/AI will be live in
v3.x.

```
make build              # default binary
make build-noai         # excludes all AI code (verified)
make build-notui        # excludes the TUI
make build-noweb        # excludes the Web UI
make build-cross        # cross-compile to linux/{amd64,arm64,386,arm/v7}
```

## Privacy posture

hostveil is local-first by default. The state.db and the report
files are stored under `$XDG_DATA_HOME/hostveil/`, which by default
is `~/.local/share/hostveil/`. Nothing leaves the host unless
one of the following is true:

- The user passes `--refresh-cve` (a CVE-feed refresh is
  attempted against the configured source — NVD or OSV).
- The user passes `--refresh-packages` (the package manager
  metadata is refreshed; this is local to the distro).
- The user invokes the AI layer (`--ai`) and has a cloud
  provider configured. Cloud providers receive a redacted
  prompt per `contracts/ai.md` after a one-time consent flow.
- The user explicitly publishes a report (manual action, not
  done by the program).

The persisted report file is redacted per
`contracts/report.md` §"Redaction" before write: PEM private
keys, named credential fields, URL credentials, and AWS access
keys are stripped.

The auth token for `hostveil web` is never persisted; only its
SHA-256 fingerprint is. The token is regenerated on every web
process start.

## Versioning

hostveil follows semantic versioning:

- **MAJOR** for incompatible governance or principle changes
  (Constitution).
- **MINOR** for new principles or materially expanded guidance.
- **PATCH** for clarifications, typo fixes, non-semantic
  refinements.

The binary's `version` and `commit` come from `git describe`
embedded at build time by `scripts/build.sh`. The first v3
release should tag `v3.0.0` so the build script reports
`v3.0.0` (not `v2.5.2-12-gHASH-dirty` from the leftover v2 tag
in the repository's history).

## License

GPL v3, inherited from the v2.5.2 codebase. See `LICENSE`.
