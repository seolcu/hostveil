# AGENTS.md

Context for AI coding assistants on this repo. Not a substitute for README.

## Project Status

**v1.0.0** — Complete rewrite of hostveil from Rust (v0.29) to Go + Bubbletea.
Branch: `main` (rewrite completed, merged from `v1.0.0-rewrite`).

## Tech Stack

- **Language**: Go 1.24+
- **TUI**: `charmbracelet/bubbletea`, `bubbles`, `lipgloss`, `glamour`, `huh`
- **YAML**: `goccy/go-yaml` (NOT `gopkg.in/yaml.v3` — it's archived)
- **Build**: `go build`, no CGO needed
- **Cross-compile**: `GOOS=linux GOARCH=arm64 go build` (native, no toolchain needed)

## Project Structure

```
hostveil/
├── cmd/hostveil/main.go              # Entry point (no flags needed, auto-discovers everything)
├── internal/
│   ├── domain/                       # Core types (Finding, Severity, Axis, etc.)
│   ├── compose/                      # docker-compose.yml parser
│   ├── scanner/
│   │   ├── rules/                    # Rule engine + 6 core rules + service-aware
│   │   ├── host/                     # 9 host check modules
│   │   └── testdata/                 # Compose file fixtures for scanner tests
│   ├── adapter/                      # External scanner wrappers (Trivy, Dockle, Lynis, Gitleaks)
│   │   └── detect.go                 # PATH-based auto-detection (installed = auto-run)
│   ├── fix/                          # Fix engine (preview/apply compose edits)
│   ├── discovery/
│   │   └── docker.go                 # Walk up from pwd, find compose.yml files
│   ├── export/                       # JSON, SARIF, Markdown, HTML
│   ├── config/                       # CLI argument parsing
├── scripts/
│   └── lab.sh                        # Docker lab management (up/down/shell/run)
├── docker/
│   └── lab/
│       ├── Dockerfile                # Go 1.24 + Trivy + Dockle + Lynis + Gitleaks
│       ├── compose.yml               # Scanner container
│       ├── vaultwarden/compose.yml   # Target service (individual)
│       ├── jellyfin/compose.yml      # Target service (individual)
│       ├── gitea/compose.yml         # Target service (individual)
│       ├── nextcloud/compose.yml     # Target service (individual)
│       ├── nginx/compose.yml         # Target service (individual)
│       └── self-hosting-stack.yml    # All targets combined
├── Makefile
└── proto/                            # Frozen Python prototype (reference only)
```

## Design Philosophy

- **`hostveil` — no flags needed**. Auto-discovers compose files by walking up from pwd.
- **`docker compose ls`-based discovery** (no pwd walk-up). Finds running compose projects system-wide.
- **Installed adapter = auto-run**. Adapter tools found in PATH are detected and run automatically.
- **All flags removed**. `--compose`, `--output`, `--fix`, `--host-root` etc. all gone. Everything happens inside the TUI.

## Design Decisions

### Why Go over Rust
- **TUI quality**: Bubbletea's Model-View-Update produces cleaner TUI code than Ratatui's immediate mode
- **Cross-compilation**: `GOOS=linux GOARCH=arm64 go build` — native, no toolchain
- **Build speed**: ~1s vs ~3min for Rust
- **AI-friendly**: Simple syntax, no ownership/lifetime complexity
- **Testing**: Easy golden file testing for TUI (`View()` returns string)

### Design Decisions (v1.0.0)
- **No `--compose` flag**: hostveil auto-discovers compose files by walking up from the current directory (like `git`).
- **No `--output` flag**: All output modes (JSON, SARIF, Markdown, HTML) are accessible from within the TUI.
- **No `--fix` flag**: Fix operations happen inside the TUI via the fix preview/apply flow.
- **Adapters auto-detect**: If Trivy/Dockle/Lynis/Gitleaks is in PATH, it runs automatically.
- **Root by default**: hostveil assumes root access for host checks and Docker operations.

### TUI Design
- **Full background coverage**: `applyBackground()` intercepts ANSI reset codes and re-applies the theme background color, preventing terminal default from showing through
- **Footer anchored to bottom**: body padded with newlines to fill terminal height
- **Responsive 3-column layout**: width ≥100 → 3 columns, 60-99 → 2 columns, <60 → 1 column
- **Component architecture**: single-screen model (findings) with integrated overview row (area health + scan context)
- **Fix Preview**: Press `p` on a fixable finding to toggle between detail view and fix preview. Shows YAML block with 3-line context plus `- old` / `+ new` diff.
- **Findings list index numbers**: Each finding prefixed with ` 1.`, ` 2.` for easy verbal reference during review
- **Detail panel separators**: `───` line divides metadata (ID/Severity/Axis/Source/Scope/Service) from content sections
- **Search/filter disambiguation**: Search text shown with `|` separator from filter chips
- **Info message grouping**: "Discovered project" messages grouped into single summary line to reduce noise

### Service-Aware Rules Design
Go version uses data-driven tables instead of lengthy if-else chains:
- `ServiceKind` enum (iota)
- `serviceDetections` table (image name → kind mapping)
- `serviceFindings` map (kind → []findingDef with declarative conditions)

### Scan Results Contract
Single `ScanResult` type flows through all modules:
```
Scanner.Run() → ScanResult → Export (JSON/SARIF/MD/HTML)
                           → TUI (Bubbletea)
```

## HCI/UI/UX Design Principles

Terminal UIs must follow UX principles. Core rules applied to hostveil design:

- **Common Region**: Group information with borders on every panel (Borders always ON)
- **Information density**: No empty screens. Padding: vertical 0, horizontal 1-2. Empty states show centered icon + message + action guidance
- **Color + text combination**: Never convey information with color alone. Always use color + text + icon together for severity
- **Natural language**: Use `Severity: Critical` instead of `sev:critical`. No abbreviations
- **Search highlighting**: Emphasize matches with reverse video or underline
- **Fix Preview**: `- old` / `+ new` diff format for clear before/after comparison
- **Scroll indicator**: Show `▼ N more lines` when content is clipped
- **Responsive layout**: 80+ cols → 2-column, 60-79 → 1.5-column, <60 → 1-column vertical scroll
- **User control**: Cancel (esc) and reset (R) available for every action
- **Consistency**: Same meaning → same position/style. Keyboard shortcuts stay consistent

## Docker Lab

```bash
# Start the full self-hosting lab
./scripts/lab.sh up

# Run hostveil inside the lab (auto-discovers all services)
./scripts/lab.sh run

# Enter the lab container
./scripts/lab.sh shell

# Stop everything
./scripts/lab.sh down
```

The lab automatically discovers all compose files under `docker/lab/*/compose.yml`.
Services can also be managed individually:

```bash
docker compose -f docker/lab/vaultwarden/compose.yml up -d
```

## Test & Build

```sh
go build ./...          # Build all
go vet ./...            # Lint
go test -race ./...     # Test with race detector
go build -o hostveil ./cmd/hostveil/  # Build binary

# Cross-compile
GOOS=linux GOARCH=arm64 go build -o hostveil-linux-arm64 ./cmd/hostveil/
```

## Key References

- `AGENTS.md` — this file
- `internal/tui/layout.go` — Layout primitives: `Rect`, `splitColumns`, `renderCardBounded`, `joinColumns`
- `internal/tui/app.go` — Bubbletea root model, background rendering, footer anchoring
- `internal/tui/screen_findings.go` — Index numbers, detail separators, fix preview, search/filter UX
- `internal/fix/engine.go` — Fix engine with `PreviewFinding()` for per-finding YAML context diff
- `internal/scanner/rules/service_aware.go` — data-driven rule design pattern
- `internal/scanner/testdata/` — compose file test fixtures (7 scenarios)
- `scripts/lab.sh` — Docker lab management

## What NOT To Do

- Do not use `gopkg.in/yaml.v3` (archived, use `goccy/go-yaml`)
- Do not re-add i18n or LLM (explicitly removed for v1.0.0)
- Do not import Rust code or attempt to reuse it
- Do not assume Docker is available (adapters should fail gracefully)
