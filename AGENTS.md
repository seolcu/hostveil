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

7 source files, ~1070 lines. Three internal packages + TUI:

```
cmd/hostveil/main.go          — ensureSudo(re-exec), parallel scan, score, TUI
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
```

### Key dependencies

- `github.com/charmbracelet/bubbletea` v1 — TUI framework (v1 API: `tea.KeyMsg`, not `KeyPressMsg`)
- `github.com/charmbracelet/bubbles` v1 — help model, viewport
- `github.com/charmbracelet/lipgloss` v1 — styling
- Standard library: `os/exec`, `encoding/json`, `context`, `sync`

### External runtime deps

- `docker` — for `docker compose ls` (compose project discovery)
- `trivy` — for `trivy config` (IaC) + `trivy image` (CVE)
- `lynis` — for `lynis audit system` (host audit)

All three must be in `$PATH`. The process runs as root (auto re-exec via `sudo`).

## Code conventions

- All findings use `RemediationUnavailable` until the fix engine is built.
- Score is a simple severity-weight formula (Critical=4, High=3, etc., multiplied by 5).
- `truncate()` in screen.go handles negative width (returns `"…"`). Callers pass `width-N` where N is consumed chars.
- `tui.Version` is a `var` settable via `-ldflags` for releases. Defaults to `"v2.0.0-dev"`.
- TUI uses `help.Model.ShortHelpView(keys)` and `help.Model.FullHelpView(keys)` (not `ShortView`/`FullView`).
- Lynis report.dat is written to `/tmp/hostveil-lynis.dat` and cleaned up after parsing.

## What's not implemented (yet)

- Fix engine (`internal/fix/engine.go`, `actions.go`, `internal/compose/parse.go`)
- Scoring model with Axis (single flat score for now)
- TUI needs significant polish (current state is minimal)
- Tests

## Common mistakes to avoid

- Do not add `sudo` inside trivy/lynis packages — the process is always root when they run.
- `ensureSudo()` in main.go re-execs the binary via `sudo os.Args...`. It does NOT use `sudo -v`.
- Do not use `tea.KeyPressMsg` — Bubbletea v1 uses `tea.KeyMsg`.
- The `defaultKeyList` in app.go is a flat `[]key.Binding`, not a struct with methods.
- `FullHelpView` takes `[][]key.Binding`, `ShortHelpView` takes `[]key.Binding`.
- Lynis findings use stable test IDs (`AUTH-9286`) in finding ID: `"lynis.AUTH-9286"`.
