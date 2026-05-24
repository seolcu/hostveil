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
cmd/hostveil/main.go          — subcommands (setup/update/serve/web),
                                ensureSudo(re-exec), scanHost(), auto-update check
internal/
├── domain/types.go            — Finding, Severity, Source, RemediationKind, ScanResult
├── trivy/trivy.go             — ScanAll(): compose ls → config + image scan
├── lynis/lynis.go             — Scan(): lynis audit → report.dat parsing
├── tui/
│   ├── app.go                 — Bubble Tea v2 model, Update, View, key modes
│   ├── screen.go              — layout, fixed-width rows, detail panel, modals
│   └── theme.go               — 13 color themes
└── web/
    ├── server.go              — embedded HTTP server, JSON API, port reclaim
    └── assets/                — no-build HTML/CSS/JS Web UI
```

### Data flow

```
main.go → ensureSudo() → goroutine trivy.ScanAll() + goroutine lynis.Scan()
       → merge findings → calculateScore() → ScanResult

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
```

### Key dependencies

- `charm.land/bubbletea/v2` — TUI framework (`tea.KeyPressMsg`, `tea.View`, `View.AltScreen`)
- `charm.land/bubbles/v2` — help/key bindings
- `charm.land/lipgloss/v2` — styling, layout, `Layer`/`Compositor` modal overlay
- Standard library: `os/exec`, `encoding/json`, `sync`, `net/http`, `embed`, `net`

### External runtime deps

- `docker` — for `docker compose ls` (compose project discovery)
- `trivy` — for `trivy config` (IaC) + `trivy image` (CVE)
- `lynis` — for `lynis audit system` (host audit)

Tools are checked via `exec.LookPath` before each scan. Missing tools are
skipped gracefully—the TUI/Web UI still starts with whatever findings exist.
Install them with `hostveil setup`.

The process runs as root (auto re-exec via `sudo os.Args...`).

### Web UI

- `hostveil serve` and `hostveil web` scan first, then serve an embedded no-build web app.
- Default address is `127.0.0.1:8787`; override with `hostveil serve --addr HOST:PORT`.
- Endpoints:
  - `GET /` — embedded Web UI
  - `GET /api/result` — JSON `domain.ScanResult`
  - `GET /api/health` — health check
- If the target port is already in use, `internal/web` inspects `/proc/net/tcp*`, finds listener PIDs via `/proc/<pid>/fd`, sends `SIGTERM`, then `SIGKILL` if needed.
- Be careful with `--addr 0.0.0.0:PORT`: this exposes host scan results from a root process. The default must remain localhost.

### Release workflow

- `.github/workflows/release.yml` — triggered by `git tag v*`
  - runs goreleaser, uploads 4 archives (linux/darwin × amd64/arm64) to GitHub Releases
  - no local goreleaser installation needed
- `.goreleaser.yaml` — builds with `-X internal/tui.Version={{.Version}}`
- `scripts/install.sh` — curl-pipe installer with interactive dep checkbox

## Code conventions

- All findings use `RemediationUnavailable` until the fix engine is built.
- Score is a simple severity-weight formula (Critical=4, High=3, etc., multiplied by 5).
- `tui.Version` is a `var` settable via `-ldflags` for releases. Defaults to `"v2.0.0-dev"`.
- TUI returns `tea.View`, sets `View.AltScreen`, `View.BackgroundColor`, `View.ForegroundColor`, and `View.WindowTitle`.
- TUI modal overlays use Lip Gloss v2 `NewLayer`/`NewCompositor`; do not reintroduce manual ANSI string overlay slicing.
- TUI row rendering should keep fixed-width row invariants; avoid slicing styled strings.
- Web UI assets are embedded from `internal/web/assets/`; keep it no-build unless there is a strong reason to add a frontend toolchain.
- Lynis report.dat is written to `/tmp/hostveil-lynis.dat` and cleaned up after parsing.

## What's not implemented (yet)

- Fix engine (`internal/fix/engine.go`, `actions.go`, `internal/compose/parse.go`)
- Scoring model with Axis (single flat score for now)
- Persistent web settings/history/export reports
- Tests

## Common mistakes to avoid

- Do not add `sudo` inside trivy/lynis packages — the process is always root when they run.
- `ensureSudo()` re-execs via `sudo os.Args...`, NOT via `sudo -v`. Do not change this.
- Bubble Tea is v2. Use `tea.KeyPressMsg` and `tea.View`; do not revert imports to `github.com/charmbracelet/...` v1 paths.
- `hostveil serve` must default to `127.0.0.1:8787`; warn on non-local bind addresses.
- Be careful changing port reclaim logic: it intentionally kills listener PIDs for the requested port.
- Lynis findings use stable test IDs (`AUTH-9286`) in finding ID: `"lynis.AUTH-9286"`.
- `.gitignore` uses `/hostveil` (prefixed slash) to avoid ignoring `cmd/hostveil/`.
- New release via Actions: `git tag vX.Y.Z && git push origin vX.Y.Z`. Do not run goreleaser locally.
- GitHub token is injected by Actions via `${{ secrets.GITHUB_TOKEN }}`.
