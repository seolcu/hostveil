# Repository Guidelines

A focused reference for AI assistants and humans working on the
hostveil codebase. For deeper background, see
[`README.md`](README.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md), and
[`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

## Project Overview

hostveil is a single-binary Linux security scanner (Go 1.26,
~17k LoC including tests, ~8.4k excluding). It runs three backends
in parallel, merges their
findings into a single scored snapshot, and renders the snapshot
in either a terminal UI (Bubble Tea v2) or an embedded Web UI
(no frontend build step).

| Concern | Backing scanner | Public entry |
|---|---|---|
| Docker Compose misconfigurations (privileged, host network, missing `no-new-privileges`, secrets, healthcheck, etc.) | native, in-process | `internal/composeaudit.ScanAll` |
| Container image CVEs | [Trivy](https://github.com/aquasecurity/trivy) | `internal/trivy.ScanAll` |
| Host hardening (SSH, kernel, file perms, audit, logging) | [Lynis](https://github.com/CISOfy/lynis) | `internal/lynis.Scan` |

Every finding has a registered fix the user can apply from either
UI. The binary ships as a single artifact (no Node, no npm, no
frontend build chain). Releases are cut on `v*` tag push via
GoReleaser.

## Architecture & Data Flow

```
                ┌────────────┐
                │  main.go   │   ensureSudo() re-execs via sudo
                └─────┬──────┘   if not already root
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
 scan.RunSingleTool  ...          ...
   "compose"        "trivy"     "lynis"
        │             │             │
        └─────────────┴─────────────┘
                      ▼
       composeaudit / trivy / lynis
                      ▼
        []domain.Finding
                      ▼
     ┌────────────────┴────────────────┐
     ▼                                 ▼
 fix.Registry.Classify        ScanProgress.AddFindings
 (remediation + how_to_fix)   (sync.RWMutex-protected)
                                    ▼
                          ScoreFindings (4-axis)
                                    ▼
                              Snapshot()  ── deep copy
                              ┌─────────┴─────────┐
                              ▼                   ▼
                       tea.NewProgram       web.Serve
                         (TUI)              (HTTP API)
```

Key invariants:
- `internal/domain` is the shared vocabulary. It has **no
  outbound** dependencies on other `internal/*` packages. Every
  other internal package imports it.
- `domain.ScanProgress` is the only type with internal
  synchronization. `AddFindings`, `SetToolStatus`, `MarkFixed`,
  `MarkRelatedFixed`, `Finalize`, `Recalculate`, `ResetForRescan`
  take the write lock; `Snapshot`, `AllToolsDone`, `ToolState`
  take the read lock. `Snapshot` returns a deep copy so the Web
  UI can poll `/api/result` without coordinating with the
  scanner goroutines.
- The Bubble Tea v2 `Update` method takes the model **by value**.
  Background goroutines push state changes via `m.send(msg)`,
  never by mutating a captured model.

**Scoring model.** `domain.ScoreFindings` returns a 0–100
`ScoreBreakdown` with per-axis scores. Each axis has its own
penalty cap so a single category cannot dominate:

| Axis | Max penalty | Source |
|---|---|---|
| Vulnerabilities | 35 | Trivy CVEs |
| Container exposure | 30 | Compose misconfigurations |
| Host hardening | 25 | Lynis findings |
| Secrets | 10 | Hardcoded secrets in compose / `.env` |

Per-finding penalty is severity-based (Critical 8, High 5, Medium
2, Low 1). Findings with `Fixed = true` are skipped. Duplicates
(same `Source`, `ID`, `Service`) are deduped. When the scan
yields zero findings the UIs show **Clean** instead of `100/100`.

**Remediation kinds.** Each finding has a `domain.RemediationKind`
set by the fix registry:
- `Auto` — one clear solution, user clicks Apply.
- `Review` — multiple valid alternatives the user picks between.
- `Manual` — cannot be automated (e.g. CVE with no `FixedVersion`).
- `Unavailable` — never user-visible after a complete scan.

## Key Directories

```
cmd/hostveil/         main package, subcommands, signal handling
                       (main.go, serve.go, history.go, scanhelp.go,
                        setup.go, update.go, tuiweb.go, util.go)
internal/
  domain/             types, scoring, scan progress (no outbound deps)
  scan/               single-tool dispatcher (RunSingleTool)
  trivy/              Trivy adapter (config + image scan)
  lynis/              Lynis adapter (host hardening)
  composeaudit/       native Docker Compose audit
  compose/            YAML AST editing primitives
  fix/                fix registry: compose, system, image fixes
                       (CRITICAL high-risk area)
  history/            checkpoints and scan history on disk
  tui/                Bubble Tea v2 UI
  web/                embedded HTTP server and static Web UI
test/e2e/             Playwright specs (Node 20+, Chromium)
scripts/              install.sh, test-install.sh
docker/               docker-in-docker test environment
                       (Dockerfile, compose fixtures, entrypoint.sh)
docs/                 ARCHITECTURE.md, DEVELOPMENT.md,
                       CONTRIBUTING.md, README.md
```

Each `internal/*` has a `README.md` documenting the public API,
file layout, and tests. Read the relevant one before editing.

## Development Commands

All four local checks must pass before you claim a change works.
Run them in order — `gofmt` is fastest, E2E is slowest.

```bash
# 1. Format check (must print nothing)
gofmt -l .

# 2. Build + vet
go build ./...
go vet ./...

# 3. Go tests with race detector
go test -race ./...

# 4. E2E browser tests (requires Node.js 20+ and Playwright)
go build -o hostveil-e2e ./cmd/hostveil/
( cd test/e2e && npm ci && npx playwright install chromium )
( cd test/e2e && npx playwright test )
rm -f hostveil-e2e test/e2e/.e2e-server-pid test/e2e/.e2e-kill.sh
rm -rf test/e2e/test-results test/e2e/playwright-report
```

Targeted feedback while iterating:

```bash
go test -race ./internal/fix/...                    # one package
go test -race ./internal/fix/... -run "TestKRNL"    # one prefix
go test -race ./internal/web/... -run "TestHandleFix"
( cd test/e2e && npx playwright test specs/dashboard.spec.ts )
( cd test/e2e && npx playwright test --grep "Score" )
```

Installer matrix (CI-only, do not run locally unless asked):
```bash
bash scripts/test-install.sh
```

Build the TUI binary and run it locally:
```bash
go build -o hostveil ./cmd/hostveil/
./hostveil                          # TUI; auto re-execs via sudo
./hostveil serve                    # Web UI on 127.0.0.1:8787
./hostveil serve --fixture test/e2e/fixtures/mock-snapshot.json --addr 127.0.0.1:8787
./hostveil --no-scan                # skip scanners, open UI immediately
./hostveil setup                    # install/update trivy and lynis
./hostveil update                   # upgrade hostveil
./hostveil history                  # list fix checkpoints
./hostveil rollback <id>            # restore pre-fix state
```

## Code Conventions & Common Patterns

### Go
- `gofmt` formatting. No exceptions.
- Every exported symbol has a GoDoc comment. Comments start with
  the symbol name, not "This" or "The". Example: `// ScoreFindings
  // returns the 0-100 breakdown for the given findings.`
- Wrap errors with `fmt.Errorf("context: %w", err)`. Never use
  `%v` for an error chain.
- No `panic` outside of `init`. No ignored errors with `_ =`
  unless a comment explains why the ignore is safe.
- No `init()` outside of `package main`.
- No exported mutable package-level state. Use a `New()` constructor
  that returns a pointer.
- Cross-platform shell scripts use `command -v` (not `which`).

### Concurrency
- The shared state between the scanner goroutines and the TUI / Web
  UI is `domain.ScanProgress`. Use its methods, never bypass the
  mutex.
- The TUI model is taken by value in `Update`. Background goroutines
  push state through `m.send(msg)` so the program loop applies it.

### Fix engine (CRITICAL — `internal/fix`)

The fix engine is the part of the codebase most likely to break in
a way that goes unnoticed. These rules are enforced by tests in
`internal/fix/system_actions_test.go` and the per-fix test files.

1. **`Review` = alternatives, not stages.** A multi-action
   `Review` fix offers independent alternatives the user can
   mix and match. The user picks ONE of N, or any subset. Each
   action must address the concern **independently**. Never
   bundle N settings into one action — the user can only
   accept all or none.
2. **A single-action fix is `Auto`, not `Review`.** Use
   `Kind: RemediationAuto` and put the concern in the action's
   `Warning` field; the UI shows a warning dialog before applying.
3. **`success=true` must have made the change.** Use `set -e` in
   shell scripts. `|| true` is allowed only for best-effort
   service start in containers without an init system. The
   regression test is `TestRunInstallAndStart_PackageFailurePropagates`.
4. **Multi-action fixes need exhaustive tests for every action
   index.** Use path-parameterized core helpers (`sshdSetOptionAt`,
   `loginDefsSetAt`, `fileAppendIfMissingAt`) so tests run against
   `t.TempDir()` files. See `system_actions_test.go` for the
   canonical pattern.
5. **Wildcard registration is for variable IDs only.** Prefer
   exact IDs so `HasExactEntry` correctly drives the related-finding
   cascade. Wildcard fixes never auto-mark related findings fixed.

### Web UI (`internal/web/assets/app.js`)
- No build step. Plain ES2020+, hand-rolled template strings, no
  JSX, no bundler. `index.html`, `app.css`, `app.js` are served
  as-is via `//go:embed assets/*`.
- Every value rendered into `innerHTML` must be HTML-escaped with
  `escapeHTML(...)`. **Browser-decoded `data-*` attribute values
  must be re-escaped on read** — `Element.dataset.foo` has already
  done entity-decoding once. The regression test is
  `test/e2e/specs/xss.spec.ts` (covers the detail panel and the
  "View more" / "View less" toggle).
- Modal overlays are `position: fixed` divs appended to
  `document.body`. They are styled with the same theme tokens as
  the main UI.
- The default bind address is `127.0.0.1:8787`. Bind to `0.0.0.0`
  only on explicit request; a one-line warning is emitted to
  stderr.

### Server security (`internal/web/server.go`)
- CSRF: `sameOrigin(origin, host)` rejects state-changing requests
  whose `Origin` does not match the `Host` header. Applies to
  `POST /api/fix`, `/api/fix/batch`, `/api/rescan`, `/api/recalc`,
  `/api/export`.
- Secure headers: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`, plus a tight `Content-Security-Policy`.
- Body cap: 1 MiB via `http.MaxBytesReader`.
- Port reclaim: only steals the port from another hostveil
  process. Refuses to steal from any other PID. Do not weaken this.
- `/api/fix` **must bounds-check `req.ActionIndex`** before
  dereferencing `f.Actions[req.ActionIndex].Label`. The regression
  test is `TestHandleFix_OutOfRangeActionIndex` in
  `internal/web/server_test.go`.

### Installer (`scripts/install.sh`)
- `scripts/install.sh.sha256` **must be regenerated on every change**
  to `install.sh`: `cd scripts && sha256sum install.sh > install.sh.sha256`.
  CI's `build` job (`sha256sum -c scripts/install.sh.sha256`) fails the
  build if they drift. `cmd/hostveil/setup.go` fetches this file from
  `main` at runtime to verify the installer before executing it — a
  stale checksum makes `hostveil setup` either hard-fail for every user
  (mismatch) or silently skip verification (if the file goes missing
  again). See `SECURITY.md`.

### Adding a fix rule
1. Read `internal/fix/README.md` and the design rules above.
2. Pick the right file: `internal/fix/compose.go`,
   `internal/fix/system.go`, or `internal/fix/images.go`.
3. `r.Register(&Fix{...})` with the right `Kind` and actions.
4. Add a test that fails before your fix and passes after.
5. For Lynis IDs, `TestLynis316_RegisteredIDsAreValid` enforces
   that every registered ID is one the parser actually emits.

### Commit and PR
- Commit message format: `area: imperative description`. `area` is
  one of `fix`, `feat`, `docs`, `test`, `refactor`, `chore`. 50
  chars or less. Examples:
  - `fix: bound-check action_index in /api/fix`
  - `feat: add KRNL-5820 core-dump fix`
  - `docs: explain the 4-axis scoring model`
- One PR per concern. If you find an unrelated bug while working,
  file it as a separate issue or PR.
- Watch CI until `build`, `test-installer`, and `e2e` are all
  green. Use `gh run watch` or the Actions API.

## Important Files

| Path | Why it matters |
|---|---|
| `cmd/hostveil/main.go` | TUI entry, subcommand dispatch, `ensureSudo()` re-exec, `runUpdateCheckBackground`, `launchScanners` |
| `cmd/hostveil/serve.go` | Web UI entry, signal handling, `--fixture` mode for E2E, TLS flags `--cert-file` / `--key-file` |
| `cmd/hostveil/history.go` | `hostveil history` and `hostveil rollback` subcommands |
| `cmd/hostveil/util.go` | `hasFlag` and `localIP` — stable, do not move |
| `internal/domain/types.go` | `Finding`, `Severity`, `Source`, `RemediationKind`, `EscapeCSV` |
| `internal/domain/scoring.go` | `ScoreFindings`, `CalculateScore`, 4-axis `scoreAxisDefs` |
| `internal/domain/live.go` | `ScanProgress` — the only type with internal synchronization |
| `internal/domain/exec.go` | `CommandRunner` interface and `DefaultRunner` |
| `internal/scan/scan.go` | `RunSingleTool`, `ScanningMessage`, `overrideCVEClassifications` (Trivy findings → Manual when no `FixedVersion`; covers GHSA-only IDs too, not just CVEs) |
| `internal/trivy/trivy.go` | `ScanAll`, `scanProject`, `runImage`, JSON decoders (image vulnerability scan only — see `internal/trivy/README.md`) |
| `internal/lynis/lynis.go` | `Scan`, `runLynis`, `parseReportFile` (4 line types: warning, suggestion, manual_event, exception_event) |
| `internal/composeaudit/audit.go` | `ScanAll`, per-project scanner |
| `internal/composeaudit/rules.go` | One function per rule; 19 `compose.dsNNN` (per-service) + 4 `compose.drNNN` (cross-cutting) rules |
| `internal/compose/edit.go` | `File`, `Open`, `SetField`, `RemoveFromList`, `Backup`, `Save`, `Diff` |
| `internal/fix/types.go` | `Action`, `Fix`, `FixResult`, `Context`, `Registry` (Lookup, Classify, HasExactEntry, WildcardMatch) |
| `internal/fix/register.go` | `RegisterAll` — wires up compose, system, and image fixes |
| `internal/fix/compose.go` | Fixes for compose misconfigurations (uses `internal/compose`) |
| `internal/fix/system.go` | Lynis-driven host fixes (uses `ActionEdit` and `ActionExec`) |
| `internal/fix/images.go` | Trivy CVE fixes (pull + redeploy; skipped without `FixedVersion`) |
| `internal/fix/edit.go` | `SimulateDiff` (dry-run) and `CaptureDiff` (real apply) for `ActionEdit` |
| `internal/history/history.go` | `Save*`, `List*`, `Get*` API; `MaxScans=30`, `MaxCheckpoints=100` (read-side caps) |
| `internal/history/rollback.go` | `Rollback(checkpoint)`, `RestartService(restart)` |
| `internal/tui/app.go` | Bubble Tea v2 `tea.Model` — `Init` / `Update` (value receiver) / `View` |
| `internal/tui/fix.go` | Fix dispatch (single + batch), dry-run, export |
| `internal/tui/screen.go` | `renderMain`, `renderLoading`, `renderDetail`, modal overlays |
| `internal/web/server.go` | HTTP server, `secureHeaders`, `sameOrigin`, `listenWithReclaim`, `handleFix` (bounds-checked) |
| `internal/web/assets/app.js` | ES2020+ SPA — `escapeHTML`, modal rendering, single global `state`, `setInterval` poll on `/api/result` |
| `internal/web/assets/index.html` | Single page shell, CSP-aware |

## Runtime/Tooling Preferences

- **Go**: 1.26.3 (`go.mod`).
- **TUI**: `charm.land/bubbletea/v2`, `charm.land/bubbles/v2`,
  `charm.land/lipgloss/v2`. Do **not** downgrade to v1
  `charmbracelet/...` paths. Use `tea.KeyPressMsg` and `tea.View`,
  not v1 APIs.
- **YAML AST**: `gopkg.in/yaml.v3` (NOT v2). The `compose` package
  keeps the original bytes alongside the parsed `yaml.Node` so
  `Diff` does not need to re-parse.
- **Embedded assets**: `//go:embed assets/*` in
  `internal/web/server.go`. Plain ES2020+, no build chain, no
  JSX, no bundler. `app.js` is served as-is.
- **External runtime deps** (skipped gracefully if missing,
  never fatal):
  - `docker` — `docker compose ls` for project discovery
  - `trivy` — container image CVEs
  - `lynis` — host hardening
- **Re-exec via sudo**: `ensureSudo()` in `cmd/hostveil/main.go`
  re-execs the current process through `sudo os.Args...` with
  `cmd.Env = os.Environ()`. Do **not** change this to `sudo -v` or
  a child-process wrapper. Host-level scanning requires root.
- **Port reclaim**: `listenWithReclaim` only kills the listener if
  it belongs to another hostveil process. Do not silently broaden
  this to non-hostveil PIDs.
- **Package manager for E2E**: `npm` (uses `npm ci`).
- **Node.js**: 20+ required for E2E; CI uses 22.
- **Playwright**: `^1.52.0` from `test/e2e/package.json`. Only
  Chromium is installed.
- **Releases**: cut on `v*` tag push via `.github/workflows/release.yml`
  + `.goreleaser.yaml`. Do not run goreleaser locally. The
  release embeds the version with
  `-X github.com/seolcu/hostveil/internal/tui.Version=v{{.Version}}`.
- **No Makefile.** No codegen. No frontend build step.
- **Linter**: `.golangci.yaml` enables only `staticcheck`,
  `ineffassign`, `misspell` (no default linter set). CI also runs
  `gofmt -l` and `go vet`.
- **.gitignore** pins `/hostveil` (prefixed slash) to avoid
  matching `cmd/hostveil/`. Do not drop the slash. E2E artifacts
  (`test/e2e/node_modules/`, `playwright-report/`, `test-results/`,
  `.e2e-server-pid`, `.e2e-kill.sh`, `hostveil-e2e` binary) are
  gitignored; do not commit them.

## Testing & QA

### Test layout
- 36 Go test files across 11 packages, ~376 test functions
  (including fuzz targets and benchmarks).
- 13 Playwright spec files in `test/e2e/specs/`:
  - `dashboard.spec.ts`, `keyboard.spec.ts`, `filters.spec.ts`,
    `selection.spec.ts` — UI navigation and key handling
  - `api-contract.spec.ts` — server contract
  - `fix-flow.spec.ts`, `fix-classification.spec.ts` — fix dispatch
  - `rescan.spec.ts`, `recalc.spec.ts` — server actions
  - `export.spec.ts` — JSON/CSV export
  - `xss.spec.ts` — **XSS regression** (the `data-*` decoding
    bug covered the detail panel and the "View more" toggle)
  - `extensive-coverage.spec.ts` — modal click-to-close,
    selection edge cases, layout/wrapping/spacing visual checks,
    filter combinations, sort interactions, rescan lifecycle,
    and empty/edge-case states
  - `responsive-visual-regressions.spec.ts` — table header
    visibility and no-document-overflow checks across viewport
    breakpoints
- Unit tests live next to the source. Integration tests
  (`internal/web`, `cmd/hostveil`) hit the public HTTP API.

### Running tests
- Race detector is required: `go test -race ./...`.
- Use `t.TempDir()` for any FS work. Never write to a real path.
- `httptest.NewServer` for HTTP. Never start a real listener.
- For tests that inject findings, call `fix.Registry.Register`
  directly. Do not mock the scanner.
- E2E builds the binary at the repo root as `hostveil-e2e` and
  serves it on `127.0.0.1:18787` (override with `E2E_PORT`) in
  fixture mode against `test/e2e/fixtures/mock-snapshot.json`.
  The helper `test/e2e/helpers/server.ts` handles build, spawn,
  health-check, and teardown.
- E2E cleanup is mandatory after the run:
  `rm -f hostveil-e2e test/e2e/.e2e-server-pid test/e2e/.e2e-kill.sh`
  and `rm -rf test/e2e/test-results test/e2e/playwright-report`.

### Coverage expectations
- A fix engine change must include a test that **fails before
  the fix and passes after it** (per `CONTRIBUTING.md`).
- Multi-action fixes need exhaustive per-action-index tests, not
  just action 0.
- Lynis fixes must satisfy `TestLynis316_RegisteredIDsAreValid`
  (every registered fix ID is one the parser actually emits).
- Server changes touching `action_index` must include
  `TestHandleFix_OutOfRangeActionIndex`-style regression coverage.
- Web UI changes touching DOM rendering must include
  `test/e2e/specs/xss.spec.ts`-style regression coverage for any
  new `innerHTML` injection site.

### CI matrix (`.github/workflows/ci.yml`)
- **`build`** — `gofmt -l`, `go build`, `go vet`, `go mod tidy`
  diff, `scripts/install.sh.sha256` verification (see below),
  `go test -race ./...`.
- **`test-installer`** — `bash scripts/test-install.sh` across
  Ubuntu 24.04, Debian bookworm, Fedora, Arch, Alpine, openSUSE
  Tumbleweed.
- **`e2e`** — `npm ci` + `npx playwright install --with-deps
  chromium` + `npx playwright test`, with the Playwright HTML
  report uploaded as an artifact on failure.

All three jobs must be green before a PR can be merged.

## Cursor Cloud specific instructions

Environment setup (Go 1.26, Node 22, `go mod download`, `npm ci`, and
Playwright Chromium) is handled by the startup update script; the four
development checks in **Development Commands** work as documented.

Non-obvious caveats for this VM:

- **Docker, `trivy`, and `lynis` are NOT installed** and root is not
  available for host scanning. All three are optional runtime deps that
  hostveil skips gracefully, so a plain `./hostveil` / `./hostveil serve`
  scan simply produces zero real findings here. To run and demo the Web
  UI (or TUI) with realistic data, use fixture mode:
  `./hostveil serve --fixture test/e2e/fixtures/mock-snapshot.json --addr 127.0.0.1:8787`
  (this is also exactly what the E2E suite runs). This is the recommended
  way to exercise the app end-to-end in the cloud environment.
- Do not run the live TUI (`./hostveil` with no `--no-scan`) expecting
  results — it re-execs via `sudo` for host scanning, which is neither
  useful nor available here.
- Playwright browsers install to `~/.cache/ms-playwright`; only Chromium
  is provisioned. The E2E run is long (~9 min, ~1900 specs). Remember the
  mandatory E2E cleanup listed under **Running tests**.
