# Tasks: Hostveil v3.0.0

**Input**: Design documents from `specs/001-selfhost-security/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/, quickstart.md
**Tests**: Tests are **mandatory** for every implementation task (Constitution Principle III, Test-First NON-NEGOTIABLE). Each implementation task is paired with a red-first test task in the same phase.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing. The TUI (US4) and Web (US5) are interleaved after US2 because they depend on the scan (US1) and fix (US2) surfaces. AI (US6) is last because it depends on explain (US3) for its input shape.

**Build tags** (set per-package, not per-task):
- `noai` — gates `internal/ai/`
- `notui` — gates `internal/tui/`
- `noweb` — gates `internal/web/`

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story this task belongs to (US1..US6)
- Include exact file paths in descriptions

## Path Conventions

This is a single Go project (CLI binary plus subcommands). Paths below match the `Project Structure` section of `plan.md`. The repository root is the working directory for all paths.

- `cmd/hostveil/` — main entry point
- `internal/` — private packages
- `tests/integration/` — end-to-end tests against a containerized host
- `tests/contract/` — public surface lock-in tests
- `test/hostimage/` — Dockerfile for the integration test host
- `scripts/` — build, test, release scripts
- `docs/` — user-facing documentation

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization, build pipeline, CI gates, and the shared scaffolding every later phase depends on.

- [ ] T001 Initialize Go module at repository root with `go.mod` (Go 1.22+), set `module github.com/<owner>/hostveil`
- [ ] T002 [P] Create the directory tree from `plan.md` §"Project Structure" (`cmd/hostveil/`, `internal/{cli,scan,checks/{ssh,docker,images,proxy,ssl,hardening},cve,fix,report,store,platform/{privilege,packagemanager,docker,sysctl},model,log,version,tui,web,ai}/`, `test/{integration,contract,hostimage}/`, `scripts/`, `docs/`)
- [ ] T003 [P] Add primary Go dependencies to `go.mod`: `github.com/spf13/cobra`, `modernc.org/sqlite`, `github.com/Masterminds/semver/v3`, `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/lipgloss`, `github.com/charmbracelet/bubbles`, `github.com/stretchr/testify`
- [ ] T004 [P] Create `scripts/build.sh` implementing the reproducible build from `research.md` R-010: `go build -trimpath -buildvcs=false` with embedded version, commit, and build date
- [ ] T005 [P] Create `scripts/test.sh` running `go test ./...` (unit), then the contract suite, then the integration suite (gated by `HOSTVEIL_INTEGRATION=1`)
- [ ] T006 [P] Create `.golangci.yml` enabling `govet`, `staticcheck`, `gofmt`, `goimports`, and an `lll` line-length cap of 100 chars
- [ ] T007 [P] Create `Makefile` with targets: `build`, `test`, `test-unit`, `test-contract`, `test-integration`, `build-noai`, `build-notui`, `build-noweb`, `lint`, `verify-noai` (CI gate)
- [ ] T008 [P] Create `LICENSE` (MIT) and stub `README.md` pointing at `docs/` (full README lands in the Polish phase)
- [ ] T009 [P] Create `.gitignore` for Go build outputs (`/vendor/`, `*.test`, `*.out`), the local `dist/` directory, and editor / OS noise. Do NOT add XDG runtime paths: those are created in `$HOME`, not in the repo, and the user's `~/.local/share/hostveil/` is never tracked.
- [ ] T010 [P] Create `.github/workflows/ci.yml` running lint, unit, contract, integration (on push), and the `verify-noai` gate (build with `-tags noai` and assert `strings` matches no `(?i)anthropic|openai|ollama`)

**Checkpoint**: `make lint && make test-unit` passes on a clean checkout. CI is green. No domain code yet.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented. Every user story depends on these.

- [ ] T011 [P] Define the canonical data model types in `internal/model/{host,service,configfile,setting,containerimage,vulnerability,finding,fix,fixrecord,scanrun,reverse_proxy,vhost,ssl_certificate,firewall_profile,hardening_baseline,system_update_status,tui_session,web_session,ai_provider,ai_request,entityref,categoryskip}.go` (all 22 entities from `data-model.md`; structs only, no behavior)
- [ ] T012 Write red tests in `internal/model/*_test.go` covering the field types, enum string values, and JSON tags for every type from T011
- [ ] T013 Implement XDG path resolution in `internal/store/path.go` returning `~/.local/share/hostveil/{reports,backups,logs}/` and `state.db` per `data-model.md` and `contracts/state-db.md` §"Storage"
- [ ] T014 Write red tests for XDG path resolution in `internal/store/path_test.go` covering the default path, `$XDG_DATA_HOME` override, and the `mkdir -p` behavior
- [ ] T015 Implement structured logging setup in `internal/log/log.go` with `log/slog` JSON handler, `scan_run_id` and `component` fields, and a `New(ctx, scanRunID)` constructor
- [ ] T016 Write red tests for the logger in `internal/log/log_test.go` covering JSON output, correlation-id propagation, and level filtering
- [ ] T017 Implement the SQLite store skeleton in `internal/store/store.go` opening the `state.db` with WAL mode, foreign keys on, busy timeout 5s, and the pragmas from `contracts/state-db.md` §"Global settings"
- [ ] T018 Implement the migrations framework in `internal/store/migrations.go` with the `schema_migrations` table; add the first migration `0001_initial.sql` creating all tables from `contracts/state-db.md` (hosts, services, config_files, settings, container_images, vulnerabilities, container_image_vulnerabilities, scan_runs, findings, fixes, fix_records, suppressions, cve_cache_meta, tui_sessions, web_sessions, ai_providers, ai_requests)
- [ ] T019 Write red tests for the store in `internal/store/store_test.go` and `internal/store/migrations_test.go` covering open/close, foreign-key enforcement, migration application, and idempotent re-application
- [ ] T020 Implement privilege elevation in `internal/platform/privilege/elevate.go` with `sudo_linux.go` (sudo adapter) and `pkexec_linux.go` (polkit adapter); the function signature accepts a list of `(name, args)` commands, batches them into a single elevation, and returns the per-command output
- [ ] T021 Write red tests for privilege elevation in `internal/platform/privilege/elevate_test.go` covering: the batching behavior, the no-op when no elevation is required, the "denied" path, and the "helper not installed" path (use a fake helper binary in a temp dir)
- [ ] T022 Implement platform detection in `internal/platform/detect_linux.go` returning the `os_family`, `os_version`, `kernel`, and `arch`; refuse to start on non-Linux (the `cmd/hostveil/main.go` calls this and prints "unsupported platform" on non-Linux per `contracts/cli.md`)
- [ ] T023 Write red tests for platform detection in `internal/platform/detect_test_linux.go` (build-tagged `_linux`) covering the four families and the unsupported-platform error
- [ ] T024 Implement the report types in `internal/report/types.go` (Go structs matching `contracts/report.md` JSON shape) and the redaction list in `internal/report/redact.go` (PEM private keys, named credential fields, URL credentials, AWS access keys)
- [ ] T025 Write red tests for the report types and redaction in `internal/report/types_test.go` and `internal/report/redact_test.go` covering the JSON tags and every redaction pattern from `contracts/report.md`
- [ ] T026 Implement common CLI flag helpers in `internal/cli/flags.go` defining `--config`, `--log-level`, `--log-file`, `--no-color`, `--color` as persistent flags; add `internal/cli/exitcode.go` with the 0/1/2 contract
- [ ] T027 Write red tests for the common flags and exit codes in `internal/cli/flags_test.go` and `internal/cli/exitcode_test.go`
- [ ] T028 Implement `cmd/hostveil/main.go` wiring cobra, the common flags, the logger, the store, the platform check, and the version output (the version constants are defined in T029)
- [ ] T029 Define `internal/version/version.go` with `Version`, `Commit`, `Built` string variables and `internal/version/buildinfo.go` exposing `String()` for the `hostveil version` output
- [ ] T030 Write a contract test in `tests/contract/version_test.go` asserting that `hostveil version` prints the shape `hostveil v3.0.0 (commit <sha>, built <RFC3339>)`

**Checkpoint**: `make build && ./hostveil version` prints the version. `make test-unit` passes all model/store/privilege/CLI tests. No user-story code yet.

---

## Phase 3: User Story 1 - Run a one-shot security scan (Priority: P1) 🎯 MVP

**Goal**: A user runs `hostveil scan` and gets a plain-language report covering every in-scope category (SSH, Docker, image CVEs, reverse proxy, SSL/TLS, system hardening).
**Independent Test**: `hostveil scan` against the pre-seeded test host (`test/hostimage/`) produces a report that contains one finding per in-scope rule, grouped by category, ordered by severity, with each finding tied to a real artifact on the host (FR-004 / SC-005 / SC-006).

### Tests for User Story 1 ⚠️

> **NOTE**: Write these tests FIRST, ensure they FAIL before implementation lands.

- [ ] T031 [P] [US1] Write `internal/checks/ssh/ssh_test.go` with table-driven tests for the SSH rules (`ssh.permit_root_login.allow`, `ssh.password_auth.only`, `ssh.protocol.legacy`) using fixture files under `internal/checks/ssh/fixtures/` (synthetic `sshd_config` snippets)
- [ ] T032 [P] [US1] Write `internal/checks/docker/docker_test.go` with table-driven tests for the Docker rules (`docker.container.runs_as_root`, `docker.container.privileged`, `docker.port.exposed_public`, `docker.compose.latest_tag`) using a mock Docker client
- [ ] T033 [P] [US1] Write `internal/checks/images/images_test.go` with table-driven tests for image-CVE matching against a fixture CVE cache
- [ ] T034 [P] [US1] Write `internal/checks/proxy/proxy_test.go` with table-driven tests for nginx and caddy rules using fixture config files
- [ ] T035 [P] [US1] Write `internal/checks/ssl/ssl_test.go` with table-driven tests for certificate expiration, auto-renewal detection, and TLS version checks using fixture certificates
- [ ] T036 [P] [US1] Write `internal/checks/hardening/hardening_test.go` with table-driven tests for the firewall, fail2ban, unattended-upgrades, sysctl, and security-update rules using fixture outputs
- [ ] T037 [P] [US1] Write `internal/scan/orchestrator_test.go` covering: per-category invocation, batched elevation, the partial/failed/success status transitions, and the scan-run row in `state.db`
- [ ] T038 [P] [US1] Write `internal/scan/fingerprint_test.go` covering the SHA-256 fingerprint computation and the `new` / `still_present` / `resolved` classification
- [ ] T039 [P] [US1] Write `internal/report/text_test.go` and `internal/report/json_test.go` covering the text and JSON rendering for a representative fixture `ScanRun`
- [ ] T040 [P] [US1] Write `internal/cve/{feed,cache,matcher,source_nvd,source_osv}_test.go` covering the feed adapter, the local cache, the matcher, and the NVD/OSV parsing

### Implementation for User Story 1

- [ ] T041 [P] [US1] Implement `internal/checks/ssh/ssh.go` (parser + rules): the SSH `ConfigFile` parser that handles `Include`, `Match` blocks, and comments, plus the three rules from T031
- [ ] T042 [P] [US1] Implement `internal/checks/docker/docker.go` (Docker socket client) and `internal/checks/docker/compose.go` (Compose parser) plus the four rules from T032
- [ ] T043 [P] [US1] Implement `internal/checks/images/images.go` (image enumeration) and the integration with `internal/cve/` (see T048) for the CVE match
- [ ] T044 [P] [US1] Implement `internal/checks/proxy/nginx.go` and `internal/checks/proxy/caddy.go` (parsers) plus the rules from T034
- [ ] T045 [P] [US1] Implement `internal/checks/ssl/cert.go` and `internal/checks/ssl/renewal.go` (cert inspection + renewal detection) plus the rules from T035
- [ ] T046 [P] [US1] Implement `internal/checks/hardening/firewall.go` (ufw/iptables/nftables detection), `fail2ban.go`, `unattended.go`, `sysctl.go` (in `internal/platform/sysctl/`), and `packages.go` (in `internal/platform/packagemanager/`)
- [ ] T047 [P] [US1] Implement `internal/platform/packagemanager/{detect,apt,dnf,pacman,apk}.go` for the four families
- [ ] T048 [P] [US1] Implement `internal/cve/{feed,cache,matcher,source_nvd,source_osv}.go` per `research.md` R-003
- [ ] T049 [US1] Implement `internal/scan/orchestrator.go` that resolves elevation needs, runs each category, writes a `ScanRun` row, and records `CategorySkip` rows for skipped categories (depends on T020, T041..T048)
- [ ] T050 [US1] Implement `internal/scan/fingerprint.go` that computes the SHA-256 fingerprint from `(category, rule_id, sorted(entity_refs))` and classifies each finding as `new` / `still_present` / `resolved` (depends on T011)
- [ ] T051 [US1] Implement `internal/report/text.go` rendering the text format per `contracts/report.md` (depends on T011, T024)
- [ ] T052 [US1] Implement `internal/report/json.go` rendering the JSON format per `contracts/report.md` (depends on T011, T024)
- [ ] T053 [US1] Implement `internal/report/sink.go` writing the report to stdout and to `--report-dir` per FR-004 / FR-019 / FR-020 (depends on T051, T052)
- [ ] T054 [US1] Implement `internal/cli/scan.go` (cobra command) and wire it into `internal/cli/root.go` (depends on T049, T050, T053)
- [ ] T055 [P] [US1] Create `test/hostimage/Dockerfile` and `test/hostimage/seed.sh` that pre-seed the test host with one finding per in-scope rule
- [ ] T056 [US1] Write the scan contract test in `tests/contract/cli_test.go` asserting the `hostveil scan` exit code (0/1/2), stdout shape, report file path, and the report's JSON sibling (depends on T054)
- [ ] T057 [US1] Write the scan integration test in `tests/integration/scan_test.go` that builds the containerized test host, runs `hostveil scan` against it, and asserts the report contains one finding per in-scope rule (depends on T055)
- [ ] T058 [US1] Write the report format contract test in `tests/contract/report_text_test.go` and `tests/contract/report_json_test.go` asserting the exact text and JSON shapes (depends on T051, T052)

**Checkpoint**: `make build && make test-integration HOSTVEIL_INTEGRATION=1` passes. `hostveil scan` produces a complete, plain-language report on a real or containerized host. This is the v3.0.0 MVP.

---

## Phase 4: User Story 2 - Apply a recommended fix safely (Priority: P2)

**Goal**: A user reviews the report, picks a finding, and applies the fix with a preview, confirmation, backup, and a guaranteed rollback path.
**Independent Test**: Apply a fix that has a backup; observe the host returns to a hardened state; roll back; observe the affected file is byte-identical to the pre-fix state (SC-003).

### Tests for User Story 2 ⚠️

- [ ] T059 [P] [US2] Write `internal/fix/{preview,backup,apply,rollback,record}_test.go` covering: the preview rendering, the backup-and-restore round trip (byte-identical SHA-256), the partial-failure reporting, the `restart_deferred` recording, and the `FixRecord` persistence
- [ ] T060 [P] [US2] Write the fix-flow contract test in `tests/contract/cli_test.go` (append to the existing file) asserting the `hostveil fix` and `hostveil rollback` subcommand shapes, exit codes, and JSON output
- [ ] T061 [P] [US2] Write the fix/rollback integration test in `tests/integration/fix_test.go` against the containerized test host

### Implementation for User Story 2

- [ ] T062 [P] [US2] Implement `internal/fix/preview.go` rendering the human-readable preview (depends on T011)
- [ ] T063 [P] [US2] Implement `internal/fix/backup.go` (XDG backup path, SHA-256 verification on restore) (depends on T013)
- [ ] T064 [US2] Implement `internal/fix/apply.go` (the minimum-elevation execution; relies on the privilege helper from T020) (depends on T020, T062, T063)
- [ ] T065 [US2] Implement `internal/fix/rollback.go` (byte-identical restore + follow-up `FixRecord`) (depends on T063, T066)
- [ ] T066 [US2] Implement `internal/fix/record.go` persisting the `FixRecord` row to `state.db` (depends on T011, T018)
- [ ] T067 [US2] Implement `internal/cli/fix.go` and `internal/cli/rollback.go` (cobra subcommands) and wire them into `root.go` (depends on T054, T064, T065)
- [ ] T068 [US2] Write the byte-identical rollback integration test in `tests/integration/rollback_test.go` asserting the SC-003 contract end to end (depends on T055, T065)
- [ ] T069 [US2] Implement `internal/fix/conflict.go` — the conflict detector per FR-011 (Match blocks, Compose override files, drop-ins under `/etc/ssh/sshd_config.d/`, and any other re-asserting construct), the plain-language list of conflicting files and lines, and the explicit `--force` override prompt (depends on T011, T062, T064)
- [ ] T070 [US2] Write the conflict-detection red tests in `internal/fix/conflict_test.go` covering each conflict shape from the FR-011 examples and the `--force` override path (depends on T069)

**Checkpoint**: A user can pick a finding from the report, apply its fix with a preview and confirmation, observe the change, and roll it back byte-for-byte. The MVP (`hostveil scan`) plus a complete fix flow is shippable.

---

## Phase 5: User Story 4 - Explore findings in an interactive TUI (Priority: P2)

**Goal**: A user runs `hostveil tui` in a real terminal and gets a keyboard-driven interface over the same findings, with explain and apply-fix actions.
**Independent Test**: Run `hostveil tui` in a PTY against the test host; navigate to the top finding; press `Enter` to expand; press `f` to apply; observe the same fix flow as the CLI. SC-007 (under 2 minutes end-to-end) is met.

### Tests for User Story 4 ⚠️

- [ ] T071 [P] [US4] Write `internal/tui/tui_test.go` (build-tagged, no `notui`) using `teatest` to drive the model: navigation, expand, fix, quit, no-tty exit, AI explain (off by default)
- [ ] T072 [P] [US4] Write the TUI contract test in `tests/contract/tui_test.go` asserting the keyboard protocol from `contracts/tui.md` and the no-tty behavior

### Implementation for User Story 4

- [ ] T073 [P] [US4] Implement `internal/tui/model.go` (the bubbletea Model: findings list, detail view, action bar) (depends on T011, T050)
- [ ] T074 [P] [US4] Implement `internal/tui/keys.go` (the key bindings from `contracts/tui.md`) (depends on T071)
- [ ] T075 [P] [US4] Implement `internal/tui/styles.go` (lipgloss styles; no-op when `--no-color` or non-TTY) (depends on T071)
- [ ] T076 [US4] Implement the TUI's "apply fix" flow by calling into `internal/fix` (depends on T064, T071)
- [ ] T077 [US4] Implement the TUI session row open/close in `internal/tui/session.go` (depends on T018, T071)
- [ ] T078 [US4] Implement `internal/tui/nopty.go` (stub when built with `notui` tag) and the build-tag-gated `internal/tui/tui.go` entry point
- [ ] T079 [US4] Implement `internal/cli/tui.go` (cobra subcommand) and wire it into `root.go` (depends on T071..T076)
- [ ] T080 [US4] Write the TUI integration test in `tests/integration/tui_test.go` driving the binary in a PTY against the test host (depends on T055, T077)

**Checkpoint**: `hostveil tui` opens, shows the findings list, lets the user navigate, expand, and apply a fix. The binary built with `-tags notui` is smaller and refuses the `tui` subcommand with a one-line message (FR-022).

---

## Phase 6: User Story 3 - Re-check the host after fixes (Priority: P3)

**Goal**: A user re-runs `hostveil scan` after applying fixes and sees what changed: `new`, `still_present`, and `resolved` findings, with a small change log.
**Independent Test**: Apply one fix; re-run `hostveil scan`; observe the previous finding is `resolved` and the new finding count decreases (SC-004).

### Tests for User Story 3 ⚠️

- [ ] T081 [P] [US3] Write `internal/cli/{explain,suppress}_test.go` covering the explain output and the suppression list behavior
- [ ] T082 [P] [US3] Write the history integration test in `tests/integration/history_test.go` asserting the `new` / `still_present` / `resolved` classification across two scans

### Implementation for User Story 3

- [ ] T083 [US3] Implement `internal/cli/explain.go` (the static, non-AI explain; plain-language what/why/how-to-verify) (depends on T011, T024)
- [ ] T084 [US3] Implement `internal/cli/suppress.go` and the suppression row in `internal/store/suppression.go` (depends on T011, T018)
- [ ] T085 [US3] Wire the suppression logic into `internal/scan/orchestrator.go` so suppressed fingerprints are recorded as `state=suppressed` (depends on T049, T082)
- [ ] T086 [US3] Write the change-log section in `internal/report/text.go` (the "Resolved findings" subsection per `contracts/report.md`) (depends on T051, T083)
- [ ] T087 [US3] Write the image-appears-fresh integration scenario in `tests/integration/history_test.go` (append) asserting US3 acceptance scenario #3: pull a new image with a known CVE, run `hostveil scan`, observe the new image's CVE reported with `state=new` and its CVE identifier + severity (depends on T055, T080)

**Checkpoint**: A second `hostveil scan` after a fix shows the previous finding as `resolved` and produces the change log. SC-004 contract verified.

---

## Phase 7: User Story 5 - View findings in a local web dashboard (Priority: P3)

**Goal**: A user runs `hostveil web` and gets a localhost-bound dashboard they can open in a browser, with the same findings, a history view, and one-click fix actions.
**Independent Test**: `hostveil web` against the test host; the dashboard first paint in under 2 s (SC-008); clicking "apply fix" runs the same flow as the CLI.

### Tests for User Story 5 ⚠️

- [ ] T088 [P] [US5] Write `internal/web/{server,handlers,auth,tls,templates}_test.go` covering: route table, auth middleware, the self-signed cert generation, the template rendering, the fix POST handler
- [ ] T089 [P] [US5] Write the Web API contract test in `tests/contract/web_test.go` using `net/http/httptest` per `contracts/web.md`
- [ ] T090 [P] [US5] Write the Web integration test in `tests/integration/web_test.go` driving the real `hostveil web` binary in a headless browser

### Implementation for User Story 5

- [ ] T091 [P] [US5] Implement `internal/web/server.go` (the `net/http` server, route table, the `srv.ListenAndServe` lifecycle) (depends on T011, T018)
- [ ] T092 [P] [US5] Implement `internal/web/auth.go` (random token, in-memory session table, constant-time compare, secure cookie) (depends on T088)
- [ ] T093 [P] [US5] Implement `internal/web/tls.go` (self-signed cert generation for non-loopback binds, user-cert loading, the printed fingerprint) (depends on T088)
- [ ] T094 [P] [US5] Implement `internal/web/templates.go` (the `html/template` set from `contracts/web.md`) (depends on T024, T088)
- [ ] T095 [P] [US5] Implement `internal/web/handlers.go` (the GET/POST handlers, all of which route through the same `internal/fix` flow as the CLI per FR-027) (depends on T064, T088)
- [ ] T096 [P] [US5] Vendor HTMX (`internal/web/htmx.go` or a static file under `internal/web/static/`) (depends on T088)
- [ ] T097 [US5] Implement `internal/web/session.go` (open/close `WebSession` row; never persist the auth token) (depends on T018, T088)
- [ ] T098 [US5] Implement `internal/web/noweb.go` (stub when built with `noweb` tag) and the build-tag-gated `internal/web/web.go` entry point
- [ ] T099 [US5] Implement `internal/cli/web.go` (cobra subcommand) and wire it into `root.go` (depends on T088..T095)
- [ ] T100 [US5] Write the auth-required-for-non-loopback test in `tests/integration/web_test.go` (append) asserting FR-025 / FR-026

**Checkpoint**: `hostveil web` opens a dashboard, lists findings, lets the user click "apply fix" with the same preview + confirmation as the CLI. The binary built with `-tags noweb` is smaller and refuses the `web` subcommand with a one-line message.

---

## Phase 8: User Story 6 - Get AI-assisted explanations and recommendations (Priority: P3)

**Goal**: A user can opt in to AI-assisted explanations and recommendations; the AI is local-first (Ollama) by default, cloud is opt-in with explicit consent; AI never applies a fix autonomously.
**Independent Test**: `hostveil ai explain <finding-id>` against the local Ollama provider returns a non-empty response in under 30 s; a fallback test (provider stopped) returns the static explanation in under 1 s (SC-009).

### Tests for User Story 6 ⚠️

- [ ] T101 [P] [US6] Write `internal/ai/{ai,redact,consent,ratelimit}_test.go` covering: the provider interface, the redaction whitelist (every entry from `contracts/ai.md`), the consent flow, and the rate limiter
- [ ] T102 [P] [US6] Write `internal/ai/provider_ollama_test.go` and `internal/ai/provider_anthropic_test.go` with httptest-based fakes for both providers
- [ ] T103 [P] [US6] Write the AI prompt contract test in `tests/contract/ai_test.go` asserting the exact prompt shape from `contracts/ai.md`
- [ ] T104 [P] [US6] Write the AI redaction contract test in `tests/contract/ai_test.go` (append) asserting that the whitelist is the only field set sent to the provider
- [ ] T105 [P] [US6] Write the AI fallback integration test in `tests/integration/ai_test.go` (provider stopped → static explanation in < 1 s)
- [ ] T106 [P] [US6] Write the `noai` binary strings-assertion CI gate in `.github/workflows/ci.yml` (already wired in T010; this task writes the assertion script)

### Implementation for User Story 6

- [ ] T107 [P] [US6] Define the `Provider` interface and registry in `internal/ai/ai.go` per `contracts/ai.md` (depends on T011)
- [ ] T108 [P] [US6] Implement `internal/ai/redact.go` (the locked whitelist from `contracts/ai.md`) (depends on T104)
- [ ] T109 [P] [US6] Implement `internal/ai/consent.go` (one-time consent prompt for cloud providers, the field-list generation) (depends on T104, T105)
- [ ] T110 [P] [US6] Implement `internal/ai/ratelimit.go` (per-provider token bucket, 3 calls / 60 s window) (depends on T104)
- [ ] T111 [P] [US6] Implement `internal/ai/provider_ollama.go` (Ollama HTTP API adapter) (depends on T104, T105)
- [ ] T112 [P] [US6] Implement `internal/ai/provider_anthropic.go` (Anthropic Messages API adapter) (depends on T104, T105)
- [ ] T113 [US6] Implement `internal/ai/provider_stub.go` (the `noai` build-tag stub) and the build-tag-gated `internal/ai/ai.go` (depends on T104)
- [ ] T114 [US6] Implement `internal/ai/persistence.go` writing the `AIProvider` and `AIRequest` rows per `contracts/state-db.md` (depends on T018, T104)
- [ ] T115 [US6] Implement `internal/cli/ai.go` (cobra subcommand family: `hostveil ai explain|risk|recommend|configure|list`) per `contracts/cli.md` (depends on T104..T111)
- [ ] T116 [US6] Wire the AI `recommend` flow into `internal/fix/apply.go` so that the resulting `FixRecord` records `recommended_by=ai:<provider>:<model>` (depends on T066, T112)
- [ ] T117 [US6] Add a `make verify-noai` target (and a CI step) that builds with `-tags noai` and asserts `strings` matches no `(?i)anthropic|openai|ollama` per SC-010 (depends on T110)

**Checkpoint**: `hostveil ai explain <id>` works against local Ollama; falls back to static on failure; never makes a network call from the default scan/fix path; the `noai` binary contains no AI literals (CI gate green).

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, release artifacts, and the final verification that every SC from the spec is met.

- [ ] T118 [P] Write `README.md` with the install instructions, the five-minute tour pointer, the philosophy, and the v3.0.0 scope per `quickstart.md`
- [ ] T119 [P] Write `docs/how-it-works.md` covering the architecture, the threat model, the build-time tag matrix, and the privacy posture
- [ ] T120 [P] Write `docs/contributing.md` with the dev setup (`make test-unit` first, TDD discipline), the build script, the test script, and the release process
- [ ] T121 [P] Write `CHANGELOG.md` with the v3.0.0 entry (full rewrite, six categories, TUI, Web, AI, noai build option)
- [ ] T122 [P] Write `scripts/release.sh` (tag, sign, attach artifacts for `linux/amd64` and `linux/arm64`; produce `hostveil_3.0.0_linux_amd64.tar.gz` and the SHA-256SUMS file per `quickstart.md`)
- [ ] T123 [P] Add the cross-build matrix in `Makefile` (`build-cross` target) producing binaries for `linux/amd64`, `linux/arm64`, `linux/386`, `linux/arm/v7` (tier-1 has CI gates; tier-2 is best-effort)
- [ ] T124 [P] Add the build-variant matrix in `Makefile` (`build-noai`, `build-notui`, `build-noweb` targets) producing the variant binaries (depends on T076, T095, T110)
- [ ] T125 Add the reproducible-build verification in `scripts/build.sh` (record the SHA-256 of the produced binary and assert it matches a CI-recorded reference) (depends on T004)
- [ ] T126 Write the final end-to-end smoke test in `tests/integration/smoke_test.go` that runs the full `quickstart.md` "Five-minute tour" against the test host and asserts every "Expected" line
- [ ] T127 Verify SC-001..SC-010 from `spec.md` end to end (a manual + automated checklist in `docs/sc-verification.md` that signs off each SC)
- [ ] T128 Update the spec quality checklist `specs/001-selfhost-security/checklists/requirements.md` if any item's pass state changed (it should not, but verify)
- [ ] T129 [P] Write `tests/integration/perf_test.go` asserting the performance budgets from the spec: SC-001 (full scan ≤ 5 min on a representative host), SC-007 (TUI session end-to-end ≤ 2 min), SC-008 (web dashboard first paint ≤ 2 s on a local connection), SC-009 (AI `explain` against local Ollama ≤ 30 s). The test file is gated by `HOSTVEIL_PERF=1` so the default CI signal stays clean; when the env var is set, the assertions run and fail on regression (depends on T055, T123)

**Checkpoint**: v3.0.0 release candidate is ready: README, docs, changelog, release script, cross-build, build variants, and the final SC verification.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies — can start immediately.
- **Foundational (Phase 2)**: depends on Setup; BLOCKS every user story.
- **US1 (Phase 3)**: depends on Foundational; the MVP, blocks all other user stories.
- **US2 (Phase 4)**: depends on US1 (findings and rules must exist).
- **US4 (Phase 5, TUI)**: depends on US1 and US2 (the TUI uses the same findings and fix flow).
- **US3 (Phase 6, re-check)**: depends on US1 and US2 (history requires a fix to have happened).
- **US5 (Phase 7, Web)**: depends on US1 and US2 (the dashboard uses the same findings and fix flow).
- **US6 (Phase 8, AI)**: depends on US1, US2, US3 (the AI takes a `Finding` produced by the scan and an explanation produced by US3).
- **Polish (Phase 9)**: depends on all user stories.

### User Story Dependencies

- **US1 (P1)**: can start after Foundational. No dependencies on other stories. This is the MVP.
- **US2 (P2)**: can start after US1. May integrate with US1's `Finding` rows but is independently testable.
- **US4 (P2, TUI)**: can start after US1 and US2. Independently testable against the test host.
- **US3 (P3)**: can start after US1 and US2. Independently testable.
- **US5 (P3, Web)**: can start after US1 and US2. Independently testable.
- **US6 (P3, AI)**: can start after US1, US2, US3. Independently testable.

### Within Each User Story

- Tests (red) MUST be written and observed failing before implementation lands (Constitution Principle III).
- Models before services.
- Services before subcommand wiring.
- Subcommand before contract tests.
- Contract tests before integration tests.

### Parallel Opportunities

- All Setup tasks marked `[P]` (T002, T003, T004, T005, T006, T007, T008, T009, T010) can run in parallel after T001.
- All Foundational tasks marked `[P]` (T011, T013, T015, T020, T022, T024, T026, T029) can run in parallel.
- Within US1, the per-category test files (T031..T036) and the per-category implementation files (T041..T048) can each be done in parallel — six independent workstreams.
- Within US1, T049 (orchestrator) and T050 (fingerprint) can run in parallel.
- Within US1, T051 (text report) and T052 (JSON report) can run in parallel.
- Within US4, US5, US6 the `[P]`-marked sub-tasks can run in parallel.
- Polish-phase `[P]` tasks (T115..T120, T121) can run in parallel.

---

## Parallel Example: User Story 1

```bash
# Phase 1: All setup tasks in parallel after the module is initialized
Task: "T002 Create directory tree per plan.md §Project Structure"
Task: "T003 Add primary Go dependencies to go.mod"
Task: "T004 Create scripts/build.sh reproducible build"
Task: "T005 Create scripts/test.sh"
Task: "T006 Create .golangci.yml"
Task: "T007 Create Makefile"
Task: "T008 Create LICENSE and stub README.md"
Task: "T009 Create .gitignore"
Task: "T010 Create .github/workflows/ci.yml"

# Phase 3 (US1): all six per-category test files in parallel
Task: "T031 [US1] Write internal/checks/ssh/ssh_test.go"
Task: "T032 [US1] Write internal/checks/docker/docker_test.go"
Task: "T033 [US1] Write internal/checks/images/images_test.go"
Task: "T034 [US1] Write internal/checks/proxy/proxy_test.go"
Task: "T035 [US1] Write internal/checks/ssl/ssl_test.go"
Task: "T036 [US1] Write internal/checks/hardening/hardening_test.go"

# Phase 3 (US1): all six per-category implementation files in parallel
Task: "T041 [US1] Implement internal/checks/ssh/ssh.go"
Task: "T042 [US1] Implement internal/checks/docker/{docker,compose}.go"
Task: "T043 [US1] Implement internal/checks/images/images.go"
Task: "T044 [US1] Implement internal/checks/proxy/{nginx,caddy}.go"
Task: "T045 [US1] Implement internal/checks/ssl/{cert,renewal}.go"
Task: "T046 [US1] Implement internal/checks/hardening/{firewall,fail2ban,unattended,sysctl,packages}.go"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: `make build && make test-integration HOSTVEIL_INTEGRATION=1`
5. The product is already useful: a non-expert can run `hostveil scan` and get a plain-language report on a real Linux host. Ship this as v3.0.0-alpha.

### Incremental Delivery

1. Setup + Foundational → Foundation ready
2. + US1 → MVP! Scan-only, shippable as v3.0.0-alpha.
3. + US2 → v3.0.0-beta. Full fix flow with rollback.
4. + US4 (TUI) → v3.0.0-beta.2. Keyboard-driven surface for non-experts.
5. + US3 (re-check) → v3.0.0-rc.1. History and `explain`.
6. + US5 (Web) → v3.0.0-rc.2. Localhost dashboard.
7. + US6 (AI) → v3.0.0. Final release with opt-in AI.
8. Each phase adds value without breaking previous phases.

### Parallel Team Strategy

With multiple developers:

1. Team completes Phase 1 (Setup) and Phase 2 (Foundational) together.
2. Once Phase 2 is done, work in parallel:
   - Developer A: US1 (Scan) — the foundation; everyone else needs it.
   - Developer B: model + store + privilege (T011..T023, which are part of Foundational; can be done alongside US1's per-category work).
   - Developer C: docs + CI (T115..T125, also parallel-safe).
3. After US1 lands, work in parallel:
   - Developer A: US2 (Fix).
   - Developer B: US4 (TUI).
   - Developer C: US3 (re-check / explain).
4. After US2 and US3 land, work in parallel:
   - Developer A: US5 (Web).
   - Developer B: US6 (AI).

---

## Notes

- `[P]` tasks = different files, no dependencies on incomplete tasks in the same phase.
- `[Story]` label maps each task to its user story for traceability.
- Each user story is independently completable and testable.
- Tests MUST be written and observed failing before implementation (Constitution Principle III).
- Build tags (`noai`, `notui`, `noweb`) are per-package; tasks that create stub files for the gated builds are explicitly marked.
- The v2.5.2 codebase is explicitly NOT carried over; do not consult it when implementing.
- Commit after each task or logical group.
- Stop at any phase checkpoint to validate the story independently.
- Avoid: vague tasks, same-file conflicts, cross-story dependencies that break independence.
