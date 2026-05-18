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
| TUI App | ~550 | Bubbletea app, 3 screens (overview/findings/history), settings modal, fix preview integration |
| TUI Overview | ~280 | Score card, severity, axis bars, action queue, host info, truncated load averages |
| TUI Findings | ~450 | Filtered list with index numbers, detail panel with section separators, fix preview (press f), search, 6 filter types, 3 sort modes, host triage empty state |
| TUI History | ~130 | Axis score bars, severity summary, warnings, grouped info messages |
| TUI Settings | ~130 | Theme selector, modal overlay, borders toggle |
| TUI Help | ~100 | Keyboard shortcut reference overlay (width 64) |
| TUI Toast | ~90 | Auto-dismissing notification with countdown indicator |
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
- **Fix Preview**: Press `f` on a fixable finding to toggle between detail view and fix preview. Preview shows the service's YAML block from the compose file with 3 lines of surrounding context, plus the proposed change summary. Uses `extractServiceSnippet()` for YAML block extraction and `PreviewFinding()` on the fix engine.
- **Findings list index numbers**: Each finding prefixed with ` 1.`, ` 2.` for easy reference. HCI motivation: users can verbally reference "finding #3" during code review.
- **Detail panel separators**: `───` line divides metadata (ID/Severity/Axis/Source/Scope/Service) from content sections (Description/Risk/Fix/Evidence). Separator defined once in the render method.
- **Search/filter disambiguation**: Search text shown with `|` separator from filter chips. Filter state shows `N/M no filters` when clean.
- **Info message grouping**: "Discovered project" messages grouped into single summary line to reduce noise. Non-project messages shown individually.

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
# Start ttyd (detached to survive shell timeouts)
setsid -f ./hostveil --serve --port 8080 --compose tests/scenarios/vaultwarden-domain/docker-compose.yml > /tmp/hostveil-serve.log 2>&1
sleep 3

# Parse actual URL from log (port may fallback from 8080)
URL=$(grep -Eo 'http://127\.0\.0\.1:[0-9]+/' /tmp/hostveil-serve.log | tail -n 1)

# Connect and focus terminal input
agent-browser open "$URL"
agent-browser set viewport 1280 720
agent-browser wait 2500
agent-browser snapshot -i
agent-browser click @e1

# Capture screenshots
agent-browser screenshot overview.png
```

### Verified TUI Keyboard Navigation (via ttyd)

All keys confirmed working through agent-browser → ttyd → Bubbletea:

| Key | Action | Verified |
|-----|--------|----------|
| `1/2/3` | Switch screens (Overview/Findings/History) | ✅ |
| `Enter` / `l` | Open finding detail panel | ✅ |
| `h` / `←` | Back to list / host triage | ✅ |
| `s` | Cycle severity filter | ✅ |
| `?` | Toggle Help overlay | ✅ |
| `S` | Toggle Settings modal | ✅ |
| `right` | Navigate Settings theme selector | ✅ |
| `f` | Toggle fix preview (on fixable findings) | ✅ |

### Visual QA Results (20 screenshots, all screens)

Captured and inspected (20 screenshots): overview, findings list, findings detail + fix preview, severity filter, empty filter, history, help, settings, theme change (before/after), host triage, narrow viewport, search mode/results, sort modes (source/title), multi-filter, theme toast, overview after theme.

- No obvious rendering breakage found
- Background colors apply correctly after ANSI reset
- Borders and panel alignment intact
- Theme changes apply immediately
- Responsive layout works at narrow viewport
- Fix preview shows service YAML block with 3-line context
- Index numbers (` 1.`, ` 2.`) present on findings list
- Detail panel has `───` section separators
- Info messages grouped: "Discovered N project(s): a, b, c"
- Load averages truncated to 1/5/15m values only
- Toast shows `%ds` countdown indicator
- **Note**: ttyd page shows browser scrollbar (container height mismatch, cosmetic only — TUI itself is fine)

### Bundled Skill: `hostveil-browser-tui-qa`

Automated screenshot capture skill at `.agents/skills/hostveil-browser-tui-qa/`:

```bash
.agents/skills/hostveil-browser-tui-qa/scripts/capture-hostveil-tui.sh
```

- Builds hostveil, starts --serve, parses fallback URL, drives TUI via agent-browser
- Captures 11 screenshots across all states
- Cleans up background processes on exit
- Validated end-to-end: script runs successfully and produces correct screenshots
- Added to git with `git add -f` (`.agents/` is ignored by default)

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
- `internal/tui/screen_findings.go` — Index numbers, detail separators, fix preview render, search/filter UX
- `internal/fix/engine.go` — Fix engine with `PreviewFinding()` for per-finding YAML context diff
- `internal/scanner/rules/service_aware.go` — data-driven rule design pattern
- `tests/scenarios/` — compose file test fixtures from v0.29
- `scripts/lab.sh` — Docker lab (v0.29 compatible)
- `.agents/skills/hostveil-browser-tui-qa/` — automated TUI screenshot QA skill
- OpenCode TUI reference: https://github.com/anomalyco/opencode (SolidJS + OpenTUI patterns)

## What NOT To Do

- Do not use `gopkg.in/yaml.v3` (archived, use `goccy/go-yaml`)
- Do not re-add i18n or LLM (explicitly removed for v1.0.0)
- Do not import Rust code or attempt to reuse it
- Do not use vhs for screenshots (unreliable Chrome process management)
- Do not add custom HTML/JS/CSS for web UI (ttyd handles it all)
- Do not assume Docker is available (adapters should fail gracefully)
