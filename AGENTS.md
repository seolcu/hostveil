# AGENTS.md

Context for AI coding assistants on this repo. Not a substitute for README.

## Project Status

**v1.0.0-rewrite** — Complete rewrite of hostveil from Rust (v0.29) to Go + Bubbletea.
Branch: `v1.0.0-rewrite` (never merged to main, `main` still has the Rust version).

## Tech Stack

- **Language**: Go 1.24+
- **TUI**: `charmbracelet/bubbletea`, `bubbles`, `lipgloss`, `glamour`, `huh`
- **YAML**: `goccy/go-yaml` (NOT `gopkg.in/yaml.v3` — it's archived)
- **Web**: `ttyd` — streams the actual Bubbletea TUI to browser via WebSocket (no custom HTML/JS/CSS)
- **Build**: `go build`, no CGO needed
- **Cross-compile**: `GOOS=linux GOARCH=arm64 go build` (native, no toolchain needed)
- **Browser screenshot**: `agent-browser` (not vhs — Chrome process management is unreliable)

## Project Structure

```
hostveil/
├── cmd/hostveil/main.go              # Entry point
├── internal/
│   ├── domain/                       # Core types (Finding, Severity, Axis, etc.)
│   ├── compose/                      # docker-compose.yml parser
│   ├── scanner/
│   │   ├── rules/                    # Rule engine + 6 core rules + service-aware
│   │   └── host/                     # 9 host check modules
│   ├── adapter/                      # External scanner wrappers (Trivy, Dockle, Lynis, Gitleaks)
│   ├── fix/                          # Fix engine (preview/apply compose edits)
│   ├── discovery/                    # Docker project discovery, host runtime info
│   ├── export/                       # JSON, SARIF, Markdown, HTML
│   ├── web/                          # ttyd launcher (50 lines): finds ttyd, starts with --serve
│   └── config/                       # CLI argument parsing
├── web/static/                       # (removed — ttyd replaces all HTML templates)
├── scripts/
│   ├── lab.sh                        # Docker lab (from v0.29, works as-is)
│   └── install.sh                    # Install script (TBD for v1.0.0)
├── Makefile
└── tests/scenarios/                  # Test compose files (from v0.29, reused)
```

## Current Implementation Status

### ✅ Completed (M1-M7, 57/62 issues closed)

| Module | Lines | Key Files |
|--------|-------|-----------|
| Domain | ~300 | `finding.go`, `severity.go`, `axis.go`, `scope.go`, `source.go`, `remediation.go`, `score.go`, `scan_result.go` |
| Compose Parser | ~400 | `parser.go` (supports long/short port syntax, volume mounts, env, cap_add, etc.) |
| Rule Engine | ~1,000 | `engine.go` + 6 core rules + `service_aware.go` (23 services) |
| Host Checks | ~400 | 9 check modules (SSH, Docker, Firewall, Kernel, Filesystem, FIM, MAC, Defenses, Updates) |
| Adapters | ~600 | Trivy, Dockle, Lynis, Gitleaks wrappers with command runner |
| Fix Engine | ~400 | preview/apply with compose edits, backup |
| Export | ~400 | JSON (with findings-only), SARIF, Markdown, HTML |
| CLI | ~100 | flag-based argument parsing |
| Discovery | ~100 | Docker compose file detection, host runtime info |
| Scanner | ~100 | Orchestration + scoring |
| TUI App | ~500 | Bubbletea app, 3 screens (overview/findings/history), settings modal |
| TUI Overview | ~260 | Score card, severity, axis bars, action queue, host info |
| TUI Findings | ~350 | Filtered list, detail panel, search, 6 filter types, 3 sort modes |
| TUI History | ~120 | Axis score bars, severity summary, warnings |
| TUI Settings | ~120 | Theme selector, modal overlay |
| TUI Help | ~100 | Keyboard shortcut reference overlay |
| TUI Toast | ~80 | Auto-dismissing notification component |
| TUI StatusBar | ~80 | Index/count/filter status bar |
| Web Server | ~50 | ttyd-backed, streams actual TUI to browser |

### 🚨 OPEN ISSUES (5 remaining) — DO NOT FORGET

These items were deferred. Must be addressed before v1.0.0 release:

| Issue | What | Reason | Mark |
|-------|------|--------|------|
| **#384** | Fix Engine — Host Edits & Shell Commands | Minimal done; full host fix list needs completion | 🟡 |
| **#385** | Fix Engine — Adapter Finding Classification | Stub only; full mapping deferred | 🟡 |
| **#386** | Adapter Integration Tests (mock adapters) | No tests yet | 🔴 |
| **#420** | TUI E2E Test Scenarios | Basic tmux script exists, needs expansion | 🔴 |
| **#422** | Docker Lab 유지보수 | scripts/lab.sh from v0.29 needs Go migration | 🔴 |

## Tests (28 tests, 5 files)

| File | Tests | Coverage |
|------|-------|----------|
| `internal/adapter/adapter_test.go` | 9 | Trivy/Dockle/Lynis/Gitleaks JSON/NDJSON parsing, timeout, edge cases |
| `internal/compose/parser_test.go` | 3 | Port/volume/env parsing, error handling, empty file |
| `internal/fix/actions_test.go` | 6 | HostEdit/ShellCmd creation, 20 host finding coverage, 4 adapter classification |
| `internal/scanner/rules/engine_test.go` | 6 | Core rules + service-aware (Vaultwarden, Postgres/Redis) |
| `internal/scanner/scanner_test.go` | 4 | Scan run, empty config, finding detection, score calculation |

Run: `go test -race -count=1 ./...`

## Design Decisions

### Why Go over Rust
- **TUI quality**: Bubbletea's Model-View-Update produces cleaner TUI code than Ratatui's immediate mode
- **Cross-compilation**: `GOOS=linux GOARCH=arm64 go build` — native, no toolchain
- **Build speed**: ~1s vs ~3min for Rust
- **AI-friendly**: Simple syntax, no ownership/lifetime complexity
- **Testing**: Easy golden file testing for TUI (`View()` returns string)

### Why ttyd instead of custom Web UI
- Single binary + ttyd = pixel-identical TUI in the browser
- No HTML templates, no CSS, no JS framework to maintain
- Full keyboard/mouse support via xterm.js WebSocket
- Font configured via `-t fontFamily=JetBrainsMono Nerd Font,Fira Code,Consolas,monospace`
- Port auto-fallback: `findPort()` probes busy ports, increments until free

### TUI Design (OpenCode-inspired)
- **Full background coverage**: `applyBackground()` intercepts ANSI reset codes (`ESC[0m`, `ESC[49m`)
  and re-applies the theme Background color, preventing terminal default background from showing
- **Footer anchored to bottom**: body padded with newlines to fill terminal height, footer always at last line
- **Responsive 3-column layout**: width ≥100 → 3 columns, 60-99 → 2 columns, <60 → 1 column
- **Component architecture**: screen models (overview/findings/history) are self-contained Bubbletea models

### Service-Aware Rules Design
Instead of 2,504 lines of Rust if-else chains (`service_aware.rs`), Go version uses data-driven tables:
- `ServiceKind` enum (iota)
- `serviceDetections` table (image name → kind mapping)
- `serviceFindings` map (kind → []findingDef with declarative conditions)
- ~440 Go lines covering all 23 services

### Scan Results Contract (ADR 0006 equivalent)
Single `ScanResult` type flows through all modules:
```
Scanner.Run() → ScanResult → Export (JSON/SARIF/MD/HTML)
                           → TUI (Bubbletea)
                           → Web Server (ttyd)
```

## Browser Screenshots (for AI visual review)

Use agent-browser (NOT vhs — Chrome process management proved unreliable):

```bash
# Start ttyd
./hostveil --serve

# In another terminal, use agent-browser to capture
agent-browser open http://127.0.0.1:PORT/
agent-browser screenshot overview.png
```

## Web Server

```bash
# Start (auto-finds free port if 8080 is busy)
./hostveil --serve

# With options
./hostveil --serve --port 9090 --compose tests/...
```

Flags:
- `--serve` — start ttyd web terminal
- `--port N` — default 8080, auto-increments if busy
- `--host ADDR` — bind address (default 127.0.0.1)

## Test & Build

```sh
go build ./...          # Build all
go vet ./...            # Lint
go test -race ./...     # Test with race detector
go build -o hostveil ./cmd/hostveil/  # Build binary

# Run with real compose file
./hostveil --compose tests/scenarios/vaultwarden-domain/docker-compose.yml

# JSON output
./hostveil --compose ... --output json

# Cross-compile
GOOS=linux GOARCH=arm64 go build -o hostveil-linux-arm64 ./cmd/hostveil/
```

## GitHub Workflow

- **8 Milestones**: M1-M8, each with ~7-11 issues
- **62 Issues total**: #367-#428
- **Branch naming**: `v1.0.0-rewrite` for the rewrite (never merge to main)
- Issues automatically close via `Closes #N` in commit messages when merged
- PRs should correspond to individual issues, not milestone batches

## Key References

- `AGENTS.md` — this file
- `internal/web/server.go` — ttyd launcher (50 lines, port fallback + font config)
- `internal/tui/app.go` — Bubbletea root model, background rendering, footer anchoring
- `internal/scanner/rules/service_aware.go` — data-driven rule design pattern
- `tests/scenarios/` — compose file test fixtures from v0.29
- `scripts/lab.sh` — Docker lab (v0.29 compatible)
- OpenCode TUI reference: https://github.com/anomalyco/opencode (SolidJS + OpenTUI patterns)

## What NOT To Do

- Do not use `gopkg.in/yaml.v3` (archived, use `goccy/go-yaml`)
- Do not re-add i18n or LLM (explicitly removed for v1.0.0)
- Do not import Rust code or attempt to reuse it
- Do not use vhs for screenshots (unreliable Chrome process management)
- Do not add custom HTML/JS/CSS for web UI (ttyd handles it all)
- Do not assume Docker is available (adapters should fail gracefully)
