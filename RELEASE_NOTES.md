# hostveil v1.0.0

Complete rewrite in Go with Bubbletea TUI. Major improvements over v0.29 (Rust).

## What's New

- **Go Rewrite** (Rust → Go 1.24+): 10x faster builds, simpler cross-compilation
- **Bubbletea TUI**: Modern Model-View-Update architecture, 5 themes, responsive layout
- **Data-Driven Rules**: Service-aware rules redesigned as clean data tables (vs 2,500-line Rust if-else chains)
- **HTMX Web UI**: Lightweight web dashboard with no JavaScript framework
- **GitHub CI/CD**: Automated testing, building, releasing via GoReleaser

## Breaking Changes

- i18n removed (English only). CJK monospace issues not worth complexity
- LLM integration removed (will return in v1.1+)
- CLI flags reorganized (see `--help`)

## Changelog

### M1 — Foundation
- Domain types: Finding, Severity, Axis, Scope, Source, Score, ScanResult
- Compose file parser with full YAML support
- Rule engine with 6 core rules + 23 service-aware rules
- 9 host check modules
- Scan orchestration with scoring

### M2 — Adapters & Fix Engine
- Trivy, Dockle, Lynis, Gitleaks adapters
- Fix engine with preview/apply for compose edits
- Host edit and shell command fix actions

### M3 — CLI & Export
- Flag-based CLI parser
- JSON, SARIF, Markdown, HTML export
- Cross-platform build support

### M4-M5 — TUI
- Bubbletea app with 3 screens (Overview, Findings, History)
- 5 visual themes (Tokyo Night, Dracula, Nord, Catppuccino, Gruvbox)
- Findings filtering (severity, source, scope, service, remediation), sorting, search
- Settings modal, help overlay, host triage mode

### M6 — Web
- net/http server with HTMX SPA
- Overview, Findings, History, Settings pages
- CSS theme switching with localStorage persistence

### M7 — CI & Packaging
- GitHub Actions: fmt → vet → test → build → smoke
- GoReleaser: deb/rpm + binary releases for linux/darwin amd64/arm64
- Install script: curl -fsSL install.sh

## Known Issues

- Scoring formula simplified (missing axis_weights, severity_deductions from v0.29)
- Fix engine YAML apply only in-memory (file writes not fully tested)
- Lynis adapter finding ID generation uses fragile string manipulation

## Contributors

- Gyuwon Seol <seolcu0112@proton.me>
