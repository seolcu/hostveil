# AGENTS.md

Context for AI coding assistants on this repo. Not a substitute for README.

## Project Status

**v1.0.0-rewrite** — Complete rewrite of hostveil from Rust (v0.29) to Go + Bubbletea.
Branch: `v1.0.0-rewrite` (never merged to main, `main` still has the Rust version).

## Tech Stack

- **Language**: Go 1.24+
- **TUI**: `charmbracelet/bubbletea`, `bubbles`, `lipgloss`, `glamour`, `huh`
- **YAML**: `goccy/go-yaml` (NOT `gopkg.in/yaml.v3` — it's archived)
- **Web**: Go `net/http` + `html/template` + HTMX (no JS framework)
- **Build**: `go build`, no CGO needed
- **Cross-compile**: `GOOS=linux GOARCH=arm64 go build` (native, no toolchain needed)

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
│   └── config/                       # CLI argument parsing
├── web/static/                       # Web SPA shell (HTMX + inline CSS)
├── scripts/
│   ├── lab.sh                        # Docker lab (from v0.29, works as-is)
│   └── install.sh                    # Install script (TBD for v1.0.0)
├── Makefile
└── tests/scenarios/                  # Test compose files (from v0.29, reused)
```

## Current Implementation Status (v1.0.0-rewrite)

### ✅ Completed (M1-M5)

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

### 🚨 DEFERRED — DO NOT FORGET

These items were intentionally deferred during M1-M3. Must be addressed before v1.0.0 release:

| Issue | What | Reason Deferred | Mark |
|-------|------|-----------------|------|
| **#384** | Fix Engine — Host Edits & Shell Commands | Minimal stub done; full coverage needs M5+ | 🟡 |
| **#385** | Fix Engine — Adapter Finding Classification | Stub only; full mapping deferred | 🟡 |
| **#386** | Adapter Integration Tests (mock adapters) | No tests yet | 🔴 |
| **#393** | Install Script + Packaging (.goreleaser.yaml, install.sh) | Not started | 🔴 |

These items were intentionally deferred during M1-M3. Must be addressed before v1.0.0 release:

| Issue | What | Reason Deferred | Mark |
|-------|------|-----------------|------|
| **#384** | Fix Engine — Host Edits & Shell Commands | Minimal stub done; full coverage needs M5+ | 🟡 |
| **#385** | Fix Engine — Adapter Finding Classification | Stub only; full mapping deferred | 🟡 |
| **#386** | Adapter Integration Tests (mock adapters) | No tests yet | 🔴 |
| **#393** | Install Script + Packaging (.goreleaser.yaml, install.sh) | Not started | 🔴 |

### ⚠️ Known Quality Gaps

| Area | Issue |
|------|-------|
| Scoring | Simplified formula (`count * severity * 5`) — missing axis_weights, severity_deductions from v0.29 |
| Fix apply | YAML content manipulation is in-memory only; actual file writes not fully tested |
| Lynis adapter | Finding ID generation uses fragile string manipulation |

### ❌ Removed from v0.29

| Feature | Reason |
|---------|--------|
| i18n (rust_i18n, 2,942 LOC YAML) | CJK breaks monospace, not worth complexity |
| LLM Integration | v1.1+ feature, was experimental |
| Web feature in Rust | Rewritten in Go with simplified scope |
| TUI in Rust | Rewritten in Go with Bubbletea |

## Design Decisions

### Why Go over Rust
- **TUI quality**: Bubbletea's Model-View-Update produces cleaner TUI code than Ratatui's immediate mode
- **Cross-compilation**: `GOOS=linux GOARCH=arm64 go build` — native, no toolchain
- **Build speed**: ~1s vs ~3min for Rust
- **AI-friendly**: Simple syntax, no ownership/lifetime complexity
- **Testing**: Easy golden file testing for TUI (`View()` returns string)

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
                           → Web Server (future)
```

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
- `internal/scanner/rules/service_aware.go` — data-driven rule design pattern
- `tests/scenarios/` — compose file test fixtures from v0.29
- `scripts/lab.sh` — Docker lab (v0.29 compatible)

## What NOT To Do

- Do not use `gopkg.in/yaml.v3` (archived, use `goccy/go-yaml`)
- Do not re-add i18n or LLM (explicitly removed for v1.0.0)
- Do not import Rust code or attempt to reuse it
- Do not add TUI before M4 (Bubbletea skeleton first, screens later)
- Do not assume Docker is available (adapters should fail gracefully)
