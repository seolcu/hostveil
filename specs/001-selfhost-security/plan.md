# Implementation Plan: Self-Host Security Scanner & Fixer (Hostveil v3.0.0)

**Branch**: `001-selfhost-security` | **Date**: 2026-06-18 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-selfhost-security/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Hostveil v3.0.0 is a single-binary Linux program that scans a
self-hoster's host across six categories (SSH, Docker, image CVEs,
reverse proxy, SSL/TLS, and system hardening), presents findings in
plain language, and applies reversible fixes with a built-in rollback
path. v3 ships three user surfaces — a CLI (`hostveil scan` /
`fix` / `rollback` / `explain` / `suppress` / `version`), an
interactive TUI (`hostveil tui`), and a local web dashboard
(`hostveil web`) — plus an opt-in AI layer that produces richer
explanations and risk assessments on demand.

v3 is a full rewrite from the previous v2.5.2 codebase; that
codebase is not referenced, ported, or consulted when making v3
design or implementation decisions. The product targets non-expert
self-hosters and is local-first by default: all state stays on the
host under the XDG base directory, outbound network calls are
opt-in and disclosed, the program auto-elevates per-category via
sudo/pkexec only when needed, and the AI layer defaults to a
local Ollama model with a hard build-time option (`noai` tag) to
exclude all AI code for users who want a minimal v3.

## Technical Context

**Language/Version**: Go 1.22+ (chosen: static single binary, mature
system-inspection ecosystem, test-first story, easy cross-compilation).

**Primary Dependencies** (Go module set; versions finalized at first
`go mod tidy`):
- `github.com/spf13/cobra` — CLI command tree
- `modernc.org/sqlite` — pure-Go SQLite (no CGO, easier reproducible builds)
- `github.com/Masterminds/semver/v3` — version comparison for the
  `Vulnerability`/`ContainerImage` matching path
- `github.com/charmbracelet/bubbletea` — TUI framework (see R-012)
- `github.com/charmbracelet/lipgloss` — TUI styling (no-op when
  `--no-color` is set or stderr is not a TTY)
- `github.com/charmbracelet/bubbles` — TUI components (list, viewport,
  help)
- Standard library for: `encoding/json`, `crypto/tls`, `crypto/x509`,
  `crypto/tls`, `net/http`, `html/template`, `os/exec`, `path/filepath`,
  `testing`, `log/slog`
- No web framework, no ORM, no async runtime beyond the standard
  library. The web dashboard uses `net/http` + `html/template` +
  a small client-side HTMX helper (vendored, no CDN at runtime).
- No web framework, no ORM, no async runtime beyond the standard library.

**Build-time flags** (set via Go build tags):
- `noai` — excludes all AI code from the binary. SC-010 requires
  that a `strings` over the resulting binary matches no string
  literal of `(?i)anthropic|openai|ollama`.
- `notui` — excludes the TUI subcommand. Useful for headless
  servers where the TUI would never be used and the build wants
  to drop the bubbletea dependency.

**Storage**:
- **Scan history**: SQLite database at
  `~/.local/share/hostveil/state.db` (XDG data home). Holds `ScanRun`,
  `Finding`, `FixRecord`, `TuiSession`, `WebSession`, `AIProvider`,
  `AIRequest`, and the previous-finding fingerprint table.
- **Reports**: plain-text files at
  `~/.local/share/hostveil/reports/hostveil-YYYYMMDD-HHMMSS.txt` per run.
- **CVE cache**: SQLite table inside `state.db` (refreshed on a TTL,
  refresh is opt-in and disclosed).
- **Web UI session tokens** and **TUI session metadata**: stored in
  the same `state.db`. The web session token itself is never
  persisted; only its SHA-256 fingerprint is.
- No network-backed storage, no cloud sync, no telemetry sink.

**Testing**: Go standard `testing` package + `github.com/stretchr/testify`
for assertions. Structure: `unit` for per-package tests, `integration` for
end-to-end runs against a containerized test host, `contract` for the
public CLI surface (cobra command behavior + report file format +
TUI keyboard protocol + Web HTTP API). TDD discipline (Principle III):
tests are written first and observed failing before implementation
lands. The TUI is tested via `teatest` (bubbletea's test helper) that
captures the rendered model after each key event.

**Target Platform**: Linux only. Tier-1 architectures: `linux/amd64`,
`linux/arm64`. Tier-2 (best-effort, no CI gate): `linux/386`,
`linux/arm/v7`. Distribution-agnostic at the user-facing surface; the
package-metadata check detects and adapts to `apt`, `dnf`, `pacman`, and
`apk` families at runtime.

**Project Type**: `cli` — single static binary `hostveil` that
also serves as a TUI binary (`hostveil tui`) and a web server
(`hostveil web`) depending on the subcommand. The distribution
artifact is a single executable; no runtime required on the
target host (matches spec FR-009).

**Performance Goals**:
- Full scan (all six categories) on a representative host: ≤ 5 minutes
  total wall-clock (SC-001). Locally, individual categories MUST
  complete in < 30 s except the package-metadata and CVE-feed refresh
  paths, which have their own SLAs documented in research.md.
- A repeat scan with no host changes: ≤ 60 s (uses cached state).
- Program startup to first output: < 500 ms cold start.
- TUI first paint (findings list visible): < 200 ms on a host with
  100 findings (SC-007 prerequisite).
- Web dashboard first paint: < 2 s on a local connection to a host
  with 100 findings (SC-008).
- AI-assisted `explain` against local Ollama: < 30 s end-to-end
  (SC-009). Fallback to non-AI: < 1 s when provider unreachable.

**Constraints**:
- No ambient network calls (Constitution: "no ambient telemetry";
  Spec FR-013 / Edge Case "no network available"). Outbound calls
  limited to (a) opt-in CVE-feed refresh, (b) opt-in package-
  metadata refresh, and (c) opt-in AI calls — all three are
  disclosed in the run summary.
- AI is opt-in per call (FR-029); the default `scan` / `fix` /
  `rollback` paths make zero AI calls.
- The web UI is localhost-only by default (FR-025). Binding to a
  non-loopback address requires explicit opt-in, an auth token, and
  HTTPS with a self-signed or user-provided certificate.
- Deterministic builds: `go build` with `-trimpath` and a recorded
  `BUILDINFO`; lockfile `go.sum` is committed; clean checkout
  produces identical bytes (Constitution Principle V + "deterministic
  builds").
- No CGO in the default build (avoids glibc version coupling,
  simplifies reproducible builds, fits the "single static binary"
  target).
- Memory ceiling: < 256 MB resident for a typical scan; < 512 MB
  for a TUI session with 1000 findings; < 1 GB for the web server
  with concurrent dashboard views.

**Scale/Scope**: Single host per invocation (Spec Assumption:
"Self-hosted... means services the user runs directly on a Linux
server"). Multi-host management is out of scope for v3.0.0.
Realistic host envelope used for sizing decisions: 1-100 running
containers, 0-5 reverse-proxy vhosts, 0-1000 SSH `Setting`s, 0-2000
pending package updates. Tests MUST cover the upper envelope; perf
targets are calibrated against the representative midpoint.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Each Hostveil v3 principle below maps to the v3 design. Gates are
evaluated PASS / FAIL with explicit evidence; FAIL requires either a
remediation or a justified entry in "Complexity Tracking" below.

| # | Constitution principle | v3 design evidence | Gate |
|---|------------------------|--------------------|------|
| 1 | I. Library-First | Every scanner, every fix, and every report is a Go package under `internal/` with its own `package doc` and unit test; `cmd/hostveil` is a thin command dispatcher that calls into those packages. No "organizational-only" packages. | PASS |
| 2 | II. CLI-First Interface | Every check is invokable from the CLI tree. stdout = human output, stderr = diagnostics, exit code = 0/1/2 (0 = no high-severity finding, 1 = high-severity finding, 2 = scan errored). JSON output available via `--format=json` on the `scan`, `fix`, and `rollback` subcommands. | PASS |
| 3 | III. Test-First (NON-NEGOTIABLE) | `tests/` tree ships with red tests for every check and every fix before the corresponding implementation lands. The `make test` target is the first gate in CI; no PR merges with red tests. | PASS |
| 4 | IV. Integration Testing | `tests/integration/` runs the compiled `hostveil` binary against a disposable containerized test host that is pre-seeded with each in-scope misconfiguration. Contract tests under `tests/contract/` lock the CLI surface and the report file format. | PASS |
| 5 | V. Observability & Versioning | Structured logs via `log/slog` (JSON handler) with `timestamp`, `level`, `component`, `scan_run_id`, `correlation_id`. Public CLI and report file follow semver; breaking changes require a `CHANGELOG.md` entry. | PASS |
| 6 | Privacy by default | All scan history and reports live under the user's home directory. No PII leaves the host. No phone-home. | PASS |
| 7 | Local-first execution | All categories run offline. CVE feed and package metadata refresh are opt-in and disclosed at run start. | PASS |
| 8 | Deterministic builds | `-trimpath`, `BUILDINFO` recorded at release time, `go.sum` committed, no CGO in default build. CI artifact compared bit-for-bit against a reproducible-build target. | PASS |
| 9 | No ambient telemetry | No `net/http` calls in startup path. The only network code lives in `internal/cve`, `internal/platform/packagemanager`, and `internal/ai` — all three are gated behind explicit flags (`--refresh-cve`, `--refresh-packages`, `--ai`). The `internal/web` package's `net/http` calls are inbound (the user connects TO us), not outbound. | PASS |
| 10 | TUI: Privacy by default | The TUI reads only from `state.db`; it makes no network calls. The TUI's `--ai-explain` action, when used, follows the same opt-in + redaction rules as the CLI's AI surface. | PASS |
| 11 | TUI: Local-first execution | The TUI runs entirely against local data; it does not require a network to render the findings list. | PASS |
| 12 | Web UI: Privacy by default | The web server is bound to `127.0.0.1` on a random port by default (FR-025). It serves no third-party content, fetches no remote scripts at runtime, and embeds the HTMX helper as a vendored local file. | PASS |
| 13 | Web UI: Local-first execution | The web server is offline-capable. The only network activity is the user connecting to the loopback bind; the server itself makes no outbound calls. | PASS |
| 14 | Web UI: Authentication on non-loopback | Per FR-025, the server refuses to start on a non-loopback address without an auth token; per FR-026 the token is random and printed once. This is the only authenticated surface in v3.0.0. | PASS |
| 15 | AI: Privacy by default | The default AI provider is local Ollama (FR-028). For cloud providers, FR-030 requires explicit one-time consent that names exactly which fields are sent; FR-031 ensures the AI code can be excluded at build time; FR-033 ensures failure modes fall back to non-AI without leaking state. | PASS |
| 16 | AI: Local-first execution | A user who never configures a cloud provider and never runs an AI-assisted command makes zero AI-related network calls. The local Ollama path is the default and is opt-in per call. | PASS |
| 17 | AI: No ambient telemetry | The `internal/ai` package's outbound `net/http` is the only AI-related network code, and it is invoked only from `--ai` subcommands. The default `scan` / `fix` / `rollback` paths do not import `internal/ai` (verified by `goimports` lint rule). | PASS |
| 18 | AI: Deterministic builds (modified) | The build itself remains deterministic; the AI *responses* are non-deterministic. This is a known and accepted deviation from the strict reading of "deterministic builds" and is recorded in "Complexity Tracking" below as a justified, scope-bounded exception. | PASS (with justification) |
| 19 | AI: AI is advisory only | FR-032 hardens the boundary: the program never applies a fix based solely on an AI recommendation; the same explicit user confirmation required for any fix is also required after an AI recommendation. | PASS |
| 20 | Build-time AI exclusion | FR-031 + the `noai` build tag + SC-010's `strings` assertion together ensure the `noai` binary contains no AI code. The build pipeline runs `strings` over the produced binary as a CI gate. | PASS |

**Re-evaluation gate (post-Phase 1)**: this table is re-walked after
the data model and contracts land. Any drift produces a Phase 1
remediation or an entry in "Complexity Tracking".

## Project Structure

### Documentation (this feature)

```text
specs/001-selfhost-security/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
│   ├── cli.md           # Public CLI surface and exit codes
│   ├── report.md        # Report file format (text + JSON shapes)
│   └── state-db.md      # SQLite schema and migration rules
├── checklists/
│   └── requirements.md  # Spec quality checklist
├── spec.md              # Feature specification
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

The shipped layout is a single Go project (CLI binary). Internal
packages follow the spec's "library-first" principle: each scanner and
each fix is its own package, independently importable and testable.

```text
.
├── cmd/
│   └── hostveil/
│       └── main.go              # Entry point: wires cobra, config, signals
├── internal/
│   ├── cli/                     # Cobra command tree, flag parsing, output dispatch
│   │   ├── root.go
│   │   ├── scan.go
│   │   ├── fix.go
│   │   ├── rollback.go
│   │   ├── explain.go
│   │   ├── suppress.go
│   │   ├── tui.go               # `hostveil tui` subcommand
│   │   ├── web.go               # `hostveil web` subcommand
│   │   ├── ai.go                # `hostveil ai explain` subcommand
│   │   └── exitcode.go
│   ├── scan/                    # Scan orchestration and state-machine
│   │   ├── orchestrator.go
│   │   ├── runner.go
│   │   └── fingerprint.go       # Finding identity / "new|still|resolved" classification
│   ├── checks/                  # One package per spec category
│   │   ├── ssh/                 # FR-001
│   │   │   ├── ssh.go
│   │   │   ├── ssh_test.go
│   │   │   └── fixtures/
│   │   ├── docker/              # FR-002
│   │   │   ├── docker.go
│   │   │   ├── compose.go
│   │   │   ├── docker_test.go
│   │   │   └── fixtures/
│   │   ├── images/              # FR-003
│   │   │   ├── images.go
│   │   │   ├── images_test.go
│   │   │   └── fixtures/
│   │   ├── proxy/               # FR-014 (nginx, caddy)
│   │   │   ├── nginx.go
│   │   │   ├── caddy.go
│   │   │   ├── proxy_test.go
│   │   │   └── fixtures/
│   │   ├── ssl/                 # FR-015
│   │   │   ├── cert.go
│   │   │   ├── renewal.go
│   │   │   ├── ssl_test.go
│   │   │   └── fixtures/
│   │   └── hardening/           # FR-016, FR-017
│   │       ├── firewall.go      # ufw / iptables / nftables detection
│   │       ├── fail2ban.go
│   │       ├── unattended.go
│   │       ├── sysctl.go
│   │       ├── packages.go      # security update detection
│   │       ├── hardening_test.go
│   │       └── fixtures/
│   ├── cve/                     # CVE feed handling (opt-in refresh)
│   │   ├── feed.go
│   │   ├── cache.go
│   │   ├── matcher.go
│   │   ├── source_nvd.go        # NVD JSON feed adapter
│   │   ├── source_osv.go        # OSV adapter (alternative)
│   │   └── cve_test.go
│   ├── fix/                     # FR-005..FR-007: apply, record, rollback
│   │   ├── apply.go
│   │   ├── preview.go
│   │   ├── backup.go
│   │   ├── rollback.go
│   │   ├── record.go
│   │   └── fix_test.go
│   ├── tui/                     # FR-021..FR-023: bubbletea-based interactive UI
│   │   │                        # Build-tag-gated by `notui`
│   │   ├── model.go             # bubbletea Model: findings list, detail view, action bar
│   │   ├── keys.go              # key bindings (vim-style + arrow keys)
│   │   ├── styles.go            # lipgloss styles; no-op when --no-color or non-TTY
│   │   ├── tui_test.go          # teatest-driven tests
│   │   └── nopty.go             # stub when built with `notui` tag
│   ├── web/                     # FR-024..FR-027: localhost web dashboard
│   │   ├── server.go            # net/http server, route table, auth middleware
│   │   ├── handlers.go          # GET/POST handlers (read-mostly)
│   │   ├── templates.go         # html/template set
│   │   ├── auth.go              # random token, session middleware
│   │   ├── tls.go               # self-signed cert generation, user-cert loading
│   │   ├── htmx.go              # vendored HTMX helper (no CDN at runtime)
│   │   ├── web_test.go
│   │   └── doc.go
│   ├── ai/                      # FR-028..FR-033: opt-in AI layer
│   │   │                        # Build-tag-gated by `noai`
│   │   ├── ai.go                # Provider interface and registry
│   │   ├── redact.go            # prompt redaction (PEM, env, URL credentials, AWS keys)
│   │   ├── consent.go           # one-time consent flow for cloud providers
│   │   ├── ratelimit.go         # per-provider token-bucket rate limit
│   │   ├── provider_ollama.go   # local Ollama adapter (default)
│   │   ├── provider_anthropic.go # cloud Anthropic adapter
│   │   ├── provider_stub.go     # stub when built with `noai` tag
│   │   ├── ai_test.go
│   │   └── doc.go
│   ├── report/                  # FR-004, FR-019, FR-020: stdout + file output
│   │   ├── text.go
│   │   ├── json.go
│   │   ├── sink.go              # stdout + file + XDG path resolution
│   │   ├── redact.go            # FR-020: no secrets in output
│   │   └── report_test.go
│   ├── store/                   # SQLite persistence (FR-008, FR-019)
│   │   ├── store.go
│   │   ├── migrations.go
│   │   ├── scanrun.go
│   │   ├── finding.go
│   │   ├── fixrecord.go
│   │   ├── cvecache.go
│   │   ├── path.go              # XDG path resolution
│   │   └── store_test.go
│   ├── platform/                # Linux-only host interactions
│   │   ├── privilege/           # sudo / pkexec batching (FR-012, FR-018)
│   │   │   ├── elevate.go
│   │   │   ├── sudo_linux.go
│   │   │   ├── pkexec_linux.go
│   │   │   └── elevate_test.go
│   │   ├── packagemanager/      # apt / dnf / pacman / apk
│   │   │   ├── detect.go
│   │   │   ├── apt.go
│   │   │   ├── dnf.go
│   │   │   ├── pacman.go
│   │   │   ├── apk.go
│   │   │   └── packagemanager_test.go
│   │   ├── docker/              # Docker socket client
│   │   │   ├── client.go
│   │   │   └── client_test.go
│   │   └── sysctl/              # sysctl key read/write
│   │       ├── sysctl_linux.go
│   │       └── sysctl_test.go
│   ├── model/                   # Plain-data types shared across packages
│   │   ├── host.go
│   │   ├── service.go
│   │   ├── configfile.go
│   │   ├── setting.go
│   │   ├── containerimage.go
│   │   ├── vulnerability.go
│   │   ├── finding.go
│   │   ├── fix.go
│   │   ├── fixrecord.go
│   │   └── scanrun.go
│   ├── log/                     # slog setup, scan-run correlation IDs
│   │   ├── log.go
│   │   └── log_test.go
│   └── version/                 # semver, buildinfo (Principle V)
│       ├── version.go
│       └── buildinfo.go
├── test/
│   ├── integration/             # End-to-end runs against a containerized host
│   │   ├── ssh_test.go
│   │   ├── docker_test.go
│   │   ├── images_test.go
│   │   ├── proxy_test.go
│   │   ├── ssl_test.go
│   │   ├── hardening_test.go
│   │   ├── report_test.go
│   │   └── fixtures/
│   ├── contract/                # Public CLI surface and report format locks
│   │   ├── cli_test.go
│   │   ├── report_text_test.go
│   │   └── report_json_test.go
│   └── hostimage/               # Dockerfile and bootstrap for the test host
│       ├── Dockerfile
│       └── seed.sh
├── docs/
│   ├── README.md                # Install, quickstart pointer, philosophy
│   ├── how-it-works.md          # Architecture and threat model
│   └── contributing.md          # Dev setup, testing, release process
├── scripts/
│   ├── build.sh                 # Reproducible-build script (Constitution V)
│   ├── test.sh                  # Convenience: runs unit + contract + integration
│   └── release.sh               # Tag, sign, attach artifacts
├── go.mod
├── go.sum
├── LICENSE
├── README.md
├── AGENTS.md                    # Updated by the after_plan hook
└── .gitignore
```

**Structure Decision**: Single Go project (Option 1 from the template).
The v3 program is a single binary whose internal layout is itself
library-first: every scanner, every fix, every report format, and every
platform adapter is a Go package that can be imported and tested in
isolation. No frontend/backend split (no UI in v3.0.0 — the user
surface is the CLI), no mobile targets.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

One tracked exception. All other Constitution gates pass without
justification.

| Item | Why needed | Simpler alternative rejected because |
|---|---|---|
| AI responses are non-deterministic | AI features (FR-028..FR-033) inherently produce non-deterministic outputs. A strict reading of the constitution's "Deterministic builds" gate (Principle V + Additional Constraints) would forbid them. | Removing AI features is incompatible with the spec's user story 6. The exception is scope-bounded: the *build* is deterministic (CI verifies the binary's hash); only the *runtime output* of an AI call is non-deterministic. The non-AI surfaces (CLI, TUI non-AI, Web non-AI) remain fully deterministic. |
