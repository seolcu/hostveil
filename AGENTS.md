# hostveil — agent guide

## Quick start

```bash
go build -o hostveil ./cmd/hostveil/
./hostveil           # re-execs via sudo automatically
./hostveil serve     # scan, then serve the Web UI on 127.0.0.1:8787
```

No Makefile. Single `main` package at `cmd/hostveil/`.

## Build & verify

```bash
go build ./...
go vet ./...
go test ./...
```

Go 1.26, module `github.com/seolcu/hostveil`.

## Architecture

Core scanner packages plus TUI and embedded Web UI:

```
cmd/hostveil/main.go          — subcommands (setup/update/serve/web/tui-web),
                                ensureSudo(re-exec), scanHost(), auto-update check
internal/
├── domain/
│   ├── types.go              — Finding, Severity, Source, RemediationKind
│   ├── scoring.go            — Axis-based scoring engine (4 axes)
│   ├── live.go               — ScanProgress, thread-safe state, Snapshot
│   └── defaults.go           — Timeouts and constants
├── scan/
│   └── scan.go               — RunSingleTool: dispatch to trivy/lynis/composeaudit, classify findings
├── trivy/
│   └── trivy.go              — ScanAll(): compose ls → config + image scan
├── composeaudit/
│   ├── audit.go              — ScanAll(): native compose YAML audit (no trivy)
│   ├── discover.go           — DiscoverProjects(): docker compose ls → config paths
│   ├── env.go                — .env file parsing for compose variable resolution
│   └── rules.go              — audit rules (privileged, host network, mounts, caps, etc.)
├── lynis/
│   └── lynis.go              — Scan(): lynis audit → report.dat parsing
├── fix/
│   ├── types.go              — Fix, Action, Registry, Classify, Run
│   ├── register.go           — RegisterAll: compose + system + image fixes
│   ├── compose.go            — Docker Compose misconfiguration fixes
│   ├── system.go             — Lynis host hardening fixes
│   ├── images.go             — CVE image pinning fixes
│   └── edit.go               — SimulateDiff, CaptureDiff
├── compose/
│   └── edit.go               — YAML document editing via yaml.v3 AST
├── tui/
│   ├── app.go                — Bubble Tea v2 model, Update, View, key modes
│   ├── screen.go             — layout, fixed-width rows, detail panel, modals
│   └── theme.go              — single color theme
└── web/
    ├── server.go             — embedded HTTP server, JSON API, port reclaim
    └── assets/               — no-build HTML/CSS/JS Web UI
```

### Data flow

```
main.go → ensureSudo() → goroutine trivy.ScanAll() + goroutine lynis.Scan()
                        → scan.RunSingleTool("composeaudit") → composeaudit.ScanAll()
       → scan.RunSingleTool → fix.Registry.Classify → merge findings
       → calculateScore() → ScanResult

Default UI:
  ScanResult → tea.NewProgram(tui.NewApp(result))

Web UI:
  hostveil serve/web → ScanResult → web.Serve(result) → / + /api/result

Subcommands (no sudo):
  hostveil setup   → bash -c "curl ...install.sh | bash"
Subcommands (sudo):
  hostveil update  → GitHub API → download tar.gz → install to /usr/bin
  hostveil serve   → scan → serve Web UI on 127.0.0.1:8787
  hostveil web     → alias for serve
  hostveil tui-web → open TUI and serve Web UI simultaneously
```

### Key dependencies

- `charm.land/bubbletea/v2` — TUI framework (`tea.KeyPressMsg`, `tea.View`, `View.AltScreen`)
- `charm.land/bubbles/v2` — help/key bindings, table, viewport, textinput
- `charm.land/lipgloss/v2` — styling, layout, `Layer`/`Compositor` modal overlay
- `gopkg.in/yaml.v3` — YAML AST manipulation for compose file editing
- Standard library: `os/exec`, `encoding/json`, `sync`, `net/http`, `embed`, `net`

### External runtime deps

- `docker` — for `docker compose ls` (compose project discovery)
- `trivy` — for `trivy config` (IaC) + `trivy image` (CVE)
- `lynis` — for `lynis audit system` (host audit)

Tools are checked via `exec.LookPath` before each scan. Missing tools are
skipped gracefully—the TUI/Web UI still starts with whatever findings exist.
Install them with `hostveil setup`.

The process runs as root (auto re-exec via `sudo os.Args...` with environment preserved).

### Web UI

- `hostveil serve` and `hostveil web` scan first, then serve an embedded no-build web app.
- Default address is `127.0.0.1:8787`; override with `hostveil serve --addr HOST:PORT`.
- Endpoints:
  - `GET /` — embedded Web UI
  - `GET /api/result` — JSON `domain.Snapshot`
  - `GET /api/health` — health check
  - `POST /api/fix` — single finding fix (supports `info_only` dry-run)
  - `POST /api/fix/batch` — batch fix multiple findings
  - `POST /api/rescan` — trigger full rescan
  - `GET /api/export?format=json|csv` — export report
- If the target port is already in use, `internal/web` inspects `/proc/net/tcp*`, finds listener PIDs via `/proc/<pid>/fd`, sends `SIGTERM`, then `SIGKILL` if needed.
- Be careful with `--addr 0.0.0.0:PORT`: this exposes host scan results from a root process. The default must remain localhost.

### Pre-flight checklist (every commit)

Before ANY commit or release, run:

```bash
# 1. Format check
gofmt -l .

# 2. Go unit + integration tests (all packages)
go build ./... && go vet ./... && go test ./...

# 3. E2E browser tests (requires Node.js + Playwright)
cd test/e2e && npx playwright test

# 4. Clean up E2E artifacts
rm -f hostveil-e2e test/e2e/.e2e-server-pid test/e2e/.e2e-kill.sh
```

All steps must pass before committing. If CI fails after push, fix and re-push immediately.

### Post-commit CI check

**The agent MUST check CI/CD results automatically after EVERY push** — never ask the user to check.

Workflow:
1. Push commit.
2. Wait for CI to complete (poll via GitHub API every 30-60s, up to 10 min).
3. Verify all jobs: `build`, `test-installer`, `e2e` all pass.
4. If any job fails: diagnose via API (check `jobs` → `steps`), fix, push again.
5. Only report to the user when ALL jobs are green.
6. The most common CI failure is unformatted Go code (`gofmt -l .` catches it locally) or transient `test-installer` Docker failures (re-run with `gh run rerun --failed`).

### Release workflow

- `.github/workflows/release.yml` — triggered by `git tag v*`
  - runs goreleaser, uploads 4 archives (linux/darwin × amd64/arm64) to GitHub Releases
  - no local goreleaser installation needed
- `.goreleaser.yaml` — builds with `-X internal/tui.Version={{.Version}}`
- `scripts/install.sh` — curl-pipe installer with interactive dep checkbox
- **After pushing a release tag, always monitor the CI/CD results** on GitHub Actions (`https://github.com/seolcu/hostveil/actions`) to confirm that the release build and all tests (Go unit + E2E) pass.

## Code conventions

- All findings use `RemediationUnavailable` until classified by `fix.Registry.Classify()`.
- Score is an axis-based model: 4 axes (Vulnerabilities, Container exposure, Host hardening, Secrets) with per-axis penalty caps.
- `tui.Version` is a `var` settable via `-ldflags` for releases. Defaults to `"v2.0.0-dev"`.
- TUI returns `tea.View`, sets `View.AltScreen`, `View.BackgroundColor`, `View.ForegroundColor`, and `View.WindowTitle`.
- TUI modal overlays use Lip Gloss v2 `NewLayer`/`NewCompositor`; do not reintroduce manual ANSI string overlay slicing.
- TUI row rendering should keep fixed-width row invariants; avoid slicing styled strings.
- Web UI assets are embedded from `internal/web/assets/`; keep it no-build unless there is a strong reason to add a frontend toolchain.
- Lynis report.dat is written to a temp file and cleaned up after parsing.
- `ensureSudo()` preserves environment variables when re-executing via sudo.

## What's not implemented (yet)

- Persistent web settings/history/scan persistence (no database, scans are in-memory only)

## RemediationKind Classification Rules

The four kinds are about FIXABILITY, not DANGER LEVEL.

- **Auto**: Software can fix it with one solution. The user still clicks "Apply".
  If the fix is dangerous, show a WARNING DIALOG. It remains Auto.
  Examples: chmod 640 /etc/shadow, sysctl -w net.ipv4.ip_forward=0
  Counter-example: "Set user: 1000:1000" should NOT be Auto if the correct UID varies per image.

- **Review**: Multiple solutions exist, OR the fix requires user input.
  NOT about danger. A safe preference choice is Review.
  Examples: "Choose bridge or overlay network", "What UID should this container use?"

- **Manual**: Technically impossible to automate. Needs a legitimate reason.
  NOT "it's hard to code" or "we haven't implemented it yet."
  Examples: LDAP requires site-specific connection details, CVE has no upstream fix yet (FixedVersion empty)
  Counter-example: CVE fix with FixedVersion available is NOT Manual — it's Auto (pull + redeploy).

- **Unavailable**: Not yet implemented. The default for all findings before Classify().

### Warning vs Review distinction
- Warning: "This fix may break things. Are you sure?" → Still Auto, show warning dialog
- Review: "Which option do you prefer?" or "What value should this be?" → Requires Review

### Review = alternatives, NOT stages

A `Review` fix represents **independent alternative solutions** the user
chooses between. The user picks ONE of N options. Each action must
address the concern **independently** — none of them depend on the
others being applied.

Counter-example (v2.5.0 mistake): KRNL-6000 was originally registered
as 1 bundled action that applied 6 sysctls together. This was wrong
because it forced the user to accept all 6 or none. A user running a
router may want `syncookies=1` but NOT `accept_source_route=0`. Reverted
to 6 separate actions so the user can pick any subset.

Correct: SSH-7408 has 5 actions (Compression, MaxAuthTries, TCPKeepAlive,
AllowAgentForwarding, MaxSessions). Each is an independent SSH
hardening choice; user can pick any subset.

A single-action fix labeled `Kind: RemediationReview` is misleading —
the user has no choice. Use `Kind: RemediationAuto` and put the
concern in the action's `Warning` field (UI shows a warning dialog
before applying).

### Action success must reflect actual state change

A fix that reports `success=true` MUST have made the expected system
change. Common silent-failure patterns to avoid:

- **Shell scripts ending in `exit 0`**: the final `exit 0` masks
  earlier failures from `set +e` or `||` chains. v2.5.0 had this bug
  in LOGG-2130, ACCT-9628, TIME-3104 install scripts.
- **`set +e` for the whole script**: install failures and start
  failures are conflated. Use `set -e` and `|| true` only on the
  best-effort step (typically service start in containers).
- **Try/catch swallowing errors**: in Go, an `Apply` function that
  ignores `err` will report success even when nothing changed.

Correct pattern: `set -e` for required steps, `|| true` for best-effort
service start. Test with `TestRunInstallAndStart_PackageFailurePropagates`
in `internal/fix/system_actions_test.go`.

### Package name aliases across distros

Some packages have different names per distro:
- `auditd` (Debian/RHEL) vs `audit` (Alpine)

The `alpinePackageAliases` map in `internal/fix/system.go` handles this.
When adding new fixes that install packages, always check both names.

### CVE finding classification
- `FixedVersion` exists → Auto: `docker compose pull` + `docker compose up -d` (with warning)
- `FixedVersion` empty → Manual: no upstream fix available yet
- The `overrideCVEClassifications` function in `scan.go` handles this after Classify()

### Dismiss feature
The dismiss feature has been removed. All findings are always visible.

## Common mistakes to avoid

- Do not add `sudo` inside trivy/lynis packages — the process is always root when they run.
- `ensureSudo()` re-execs via `sudo os.Args...` with `cmd.Env = os.Environ()`, NOT via `sudo -v`. Do not change this.
- Bubble Tea is v2. Use `tea.KeyPressMsg` and `tea.View`; do not revert imports to `github.com/charmbracelet/...` v1 paths.
- `hostveil serve` must default to `127.0.0.1:8787`; warn on non-local bind addresses.
- Be careful changing port reclaim logic: it intentionally kills listener PIDs for the requested port.
- Lynis findings use stable test IDs (`AUTH-9286`) in finding ID: `"lynis.AUTH-9286"`.
- `.gitignore` uses `/hostveil` (prefixed slash) to avoid ignoring `cmd/hostveil/`.
- New release via Actions: `git tag vX.Y.Z && git push origin vX.Y.Z`. Do not run goreleaser locally.
- GitHub token is injected by Actions via `${{ secrets.GITHUB_TOKEN }}`.

### Fix code design rules

- **Review = user picks one of N independent options.** Never bundle N
  separate settings into 1 Review action (that forces all-or-nothing).
  See "Review = alternatives, NOT stages" above for the design rule and
  KRNL-6000's history as a counter-example.
- **Single-action fixes use `Kind: RemediationAuto`**, not Review. Put
  danger warnings in the action's `Warning` field; the UI shows a
  warning dialog before applying.
- **Success must reflect actual change.** Shell scripts use `set -e`,
  not `set +e; exit 0`. Best-effort steps (e.g. `rc-service` in
  containers without init) use `|| true`. Test with
  `TestRunInstallAndStart_PackageFailurePropagates`.
- **Every multi-action Review needs exhaustive tests** for each action
  index, not just action 0. Use path-parameterized core helpers
  (`sshdSetOptionAt`, `loginDefsSetAt`, `fileAppendIfMissingAt`) so
  tests can run against `t.TempDir()` files. See
  `internal/fix/system_actions_test.go`.
