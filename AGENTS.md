# hostveil — agent guide

## Quick start

```bash
go build -o hostveil ./cmd/hostveil/
./hostveil           # re-execs via sudo automatically
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

10 source files, ~1200 lines. Three internal packages + TUI:

```
cmd/hostveil/main.go          — subcommands (setup/update/--no-update),
                                ensureSudo(re-exec), parallel scan, auto-update check
internal/
├── domain/types.go            — Finding, Severity, Source, RemediationKind, ScanResult
├── trivy/trivy.go             — ScanAll(): compose ls → config + image scan
├── lynis/lynis.go             — Scan(): lynis audit → report.dat parsing
└── tui/
    ├── app.go                 — Bubbletea model, Update, View
    ├── screen.go              — renderHeader, renderFindingsList, renderDetail, renderSettings
    └── theme.go               — 13 color themes
```

### Data flow

```
main.go → ensureSudo() → goroutine trivy.ScanAll() + goroutine lynis.Scan()
       → merge findings → calculateScore() → tea.NewProgram(TUI)

Subcommands (no sudo):
  hostveil setup   → bash -c "curl ...install.sh | bash"
  hostveil update  → GitHub API → download tar.gz → install to /usr/bin
```

### Key dependencies

- `github.com/charmbracelet/bubbletea` v1 — TUI framework (v1 API: `tea.KeyMsg`, not `KeyPressMsg`)
- `github.com/charmbracelet/bubbles` v1 — help model, viewport
- `github.com/charmbracelet/lipgloss` v1 — styling
- Standard library: `os/exec`, `encoding/json`, `context`, `sync`, `net/http`

### External runtime deps

- `docker` — for `docker compose ls` (compose project discovery)
- `trivy` — for `trivy config` (IaC) + `trivy image` (CVE)
- `lynis` — for `lynis audit system` (host audit)

Tools are checked via `exec.LookPath` before each scan. Missing tools are
skipped gracefully—the TUI still starts with whatever findings exist.
Install them with `hostveil setup`.

The process runs as root (auto re-exec via `sudo os.Args...`).

### Release workflow

- `.github/workflows/release.yml` — triggered by `git tag v*`
  - runs goreleaser, uploads 4 archives (linux/darwin × amd64/arm64) to GitHub Releases
  - no local goreleaser installation needed
- `.goreleaser.yaml` — builds with `-X internal/tui.Version={{.Version}}`
- `scripts/install.sh` — curl-pipe installer with interactive dep checkbox

## Code conventions

- All findings use `RemediationUnavailable` until the fix engine is built.
- Score is a simple severity-weight formula (Critical=4, High=3, etc., multiplied by 5).
- `truncate()` in screen.go handles negative width (returns `"…"`). Callers pass `width-N` where N is consumed chars.
- `tui.Version` is a `var` settable via `-ldflags` for releases. Defaults to `"v2.0.0-dev"`.
- TUI uses `help.Model.ShortHelpView(keys)` and `help.Model.FullHelpView(keys)`.
- Lynis report.dat is written to `/tmp/hostveil-lynis.dat` and cleaned up after parsing.

## What's not implemented (yet)

- Fix engine (`internal/fix/engine.go`, `actions.go`, `internal/compose/parse.go`)
- Scoring model with Axis (single flat score for now)
- TUI needs significant polish (current state is minimal)
- Tests

## Common mistakes to avoid

- Do not add `sudo` inside trivy/lynis packages — the process is always root when they run.
- `ensureSudo()` re-execs via `sudo os.Args...`, NOT via `sudo -v`. Do not change this.
- Do not use `tea.KeyPressMsg` — Bubbletea v1 uses `tea.KeyMsg`.
- The `defaultKeyList` in app.go is a flat `[]key.Binding`, not a struct.
- `FullHelpView` takes `[][]key.Binding`, `ShortHelpView` takes `[]key.Binding`.
- Lynis findings use stable test IDs (`AUTH-9286`) in finding ID: `"lynis.AUTH-9286"`.
- `.gitignore` uses `/hostveil` (prefixed slash) to avoid ignoring `cmd/hostveil/`.
- New release via Actions: `git tag vX.Y.Z && git push origin vX.Y.Z`. Do not run goreleaser locally.
- GitHub token is injected by Actions via `${{ secrets.GITHUB_TOKEN }}`.
