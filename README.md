# hostveil

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![Status: Active](https://img.shields.io/badge/status-active-brightgreen)](https://github.com/seolcu/hostveil)

> **hostveil** — Linux self-hosting security dashboard. Zero-config, terminal-native, adapter-aware.

Inspired by Chrome Lighthouse and `btop`, hostveil scans your Docker Compose stacks and host environment for security misconfigurations — then presents everything in one interactive TUI. Just run `hostveil`.

**[English](README.md)** | [한국어](README.ko.md)

---

## Philosophy

**`hostveil` — no flags needed.** Auto-discovers everything:

- Walks up from `pwd` to find compose files.
- Detects Trivy, Dockle, Lynis, Gitleaks in `PATH` and runs them automatically.
- Scores findings across five audit axes in a rich Bubbletea TUI.

No `--compose`, `--output`, `--fix`, or `--adapters` flags. Only `--serve`, `--port`, `--host`, `--user-mode`, `--version`. Run as root for full coverage; use `--user-mode` to restrict.

---

## Quick Start

```sh
# Interactive TUI (auto-discovers everything)
hostveil

# Web UI via ttyd (http://127.0.0.1:8080)
hostveil --serve

# Restricted privileges
hostveil --user-mode
```

Just `hostveil`. It finds compose files, runs rules, detects adapter tools, and opens a TUI with overview, findings, and history screens.

---

## Features

### Compose Scanner — 7 Rule Categories

| Rule | What It Checks |
|------|---------------|
| **Exposure** | Public port bindings (`0.0.0.0`), services that need a reverse proxy |
| **Permissions** | `privileged: true`, root user, `SYS_ADMIN`, sensitive host mounts |
| **Runtime** | `no-new-privileges` disabled, writable root filesystem |
| **Sensitive Data** | Inline secrets in env vars, default/weak credentials |
| **Updates** | Missing version pins, `:latest` tag |
| **Network** | Default bridge network, `network_mode: host` |
| **Service-Aware** | 23 services — Vaultwarden, Jellyfin, Gitea, Nextcloud, Immich, Traefik, Portainer, Home Assistant, Pi-hole, Grafana, NPM, Caddy, Authentik, Paperless, Postgres, MySQL, Redis, GitLab, Uptime Kuma, Duplicati, Restic, Borg, Kopia |

### Host Auditing — 9 Check Modules

| Module | What It Checks |
|--------|---------------|
| **SSH** | PermitRootLogin, password auth, protocol version |
| **Docker** | Daemon socket exposure, user-namespace remapping |
| **Firewall** | Active firewall (iptables/nftables/ufw), default policies |
| **Kernel** | sysctl hardening, ASLR, YAMA ptrace |
| **Filesystem** | World-writable dirs, noexec mounts |
| **FIM** | File integrity monitoring (AIDE, Tripwire) |
| **MAC** | Mandatory access control (AppArmor, SELinux) |
| **Defenses** | Fail2ban, auditd, rkhunter |
| **Updates** | Unattended-upgrades, pending reboot |

### External Adapters — Installed = Auto-Run

| Adapter | Purpose |
|---------|---------|
| **Trivy** | Container image vulnerability scanning |
| **Dockle** | Docker image best-practices linter |
| **Lynis** | Host-level security auditing |
| **Gitleaks** | Git secret/credential leak detection |

No config needed. Available tools are detected at startup and their results merge into the findings list.

### Fix Engine

Guided remediation for compose files and host configs:

- **Preview** changes before applying (press `f` on any fixable finding).
- **Auto** — applied on confirm (pin tags, drop caps).
- **Review** — user input needed (bind port to `127.0.0.1`).
- **Manual** — instructions provided when automation isn't possible.
- **Backups** — original files are backed up before edits.
- **Host + adapter fixes** — shell commands for SSH, firewall, Trivy updates, Gitleaks cleanup.

### Export

Available from the History screen:

| Format | Use Case |
|--------|----------|
| **JSON** | Machine-readable, pipeline integration |
| **SARIF** | Static analysis interchange (SIEM, CodeQL) |
| **Markdown** | Human-readable reports, PR comments |
| **HTML** | Rich formatted reports for stakeholders |

### Web UI (ttyd)

```sh
hostveil --serve --port 8080 --host 127.0.0.1
```

Streams the real Bubbletea TUI to your browser via ttyd WebSocket. Handles port conflicts by freeing the occupied port.

### TUI Themes

9 themes: Default ANSI, Catppuccin, Nord, Tokyo Night, Gruvbox, Dracula, Monokai, Light, Solarized Light.

---

## Installation

### GitHub Releases (recommended)

```sh
curl -fsSL https://github.com/seolcu/hostveil/releases/latest/download/hostveil_linux_amd64 -o /usr/local/bin/hostveil
chmod +x /usr/local/bin/hostveil
```

Architectures: `amd64`, `arm64`. Linux and macOS.

### Go Install

```sh
go install github.com/seolcu/hostveil/cmd/hostveil@latest
```

Requires Go 1.24+.

### Docker

```sh
docker pull ghcr.io/seolcu/hostveil:latest
```

---

## Build from Source

Go 1.24+, no CGO.

```sh
git clone https://github.com/seolcu/hostveil.git
cd hostveil
go build -o hostveil ./cmd/hostveil/

# Cross-compile (native, no toolchain)
GOOS=linux GOARCH=arm64 go build -o hostveil-linux-arm64 ./cmd/hostveil/
GOOS=darwin GOARCH=amd64 go build -o hostveil-darwin-amd64 ./cmd/hostveil/
```

Or use Makefile: `make build`, `make cross`, `make test`.

---

## Usage

### TUI Screens

| Key | Screen | Content |
|-----|--------|---------|
| `1` | **Overview** | Score card, axis breakdown, action queue, adapter status, host info |
| `2` | **Findings** | Severity-sorted list, detail panel, fix guidance, filters, search |
| `3` | **History** | Score trends, severity summary, export buttons |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `f` | Fix preview for selected finding |
| `/` | Search findings |
| `s` | Settings (theme, layout, borders) |
| `?` | Help overlay |
| `Tab` | Cycle panel focus |
| `q` / `Esc` | Quit or back |
| `L` | Cycle layout presets |

### Findings Screen

- Sorted by severity (Critical → High → Medium → Low).
- Filter by source (compose/host/adapter), remediation type (auto/review/manual), or service.
- Three sort modes: severity, service, axis.
- Press `f` on fixable findings to enter the fix preview workflow.

### Fix Engine Workflow

1. Select a fixable finding (`Auto` or `Review` type).
2. Press `f` — preview panel shows the diff and action summary.
3. Confirm — engine backs up the original file and applies the fix.

### Export

From History screen, export to JSON, SARIF, Markdown, or HTML.

---

## Target Audit Axes

Every finding maps to one of five axes. The TUI shows per-axis scores alongside the overall score.

| Axis | What It Covers | Examples |
|------|---------------|----------|
| **Sensitive Data** | Secrets, credentials, confidential exposure | `.env` files, plain-text passwords, inline tokens, volume-mounted secrets |
| **Excessive Permissions** | Over-privileged containers, broad access | `privileged: true`, root user, `SYS_ADMIN`, mounts of `/etc/shadow` or `/var/run/docker.sock` |
| **Unnecessary Exposure** | Attack surface from network exposure | Public port bindings (`0.0.0.0`), missing reverse proxy, `network_mode: host` |
| **Update & Supply Chain** | Image and dependency risks | `:latest` tag, unpinned versions, stale images, no CVE scanning |
| **Host Hardening** | Linux host security posture | SSH config, firewall, Docker daemon, kernel params, AppArmor/SELinux, Fail2ban |

---

## Docker Lab

Complete lab environment for development and testing. Spins up a scanner container with all tools pre-installed plus five intentionally-vulnerable compose stacks.

### Prerequisites

Docker (Compose V2), Git.

### Setup

```sh
cd hostveil
./scripts/lab.sh up
```

Builds the lab container (Go 1.24, ttyd, Trivy, Dockle, Lynis, Gitleaks) and starts Vaultwarden, Jellyfin, Gitea, Nextcloud, and nginx — each with deliberate security flaws.

### Lab Commands

```sh
./scripts/lab.sh up              # Start lab (scanner + all targets)
./scripts/lab.sh down            # Stop all lab services
./scripts/lab.sh shell           # Enter lab container (bash)
./scripts/lab.sh run             # Run hostveil inside lab (auto-discovery)
./scripts/lab.sh serve           # hostveil --serve at http://localhost:9090/
./scripts/lab.sh serve-detached  # hostveil --serve in detached mode
```

Target services can also be started individually:

```sh
docker compose -f docker/lab/vaultwarden/compose.yml up -d
```

### Lab Architecture

```
┌──────────────────────┐
│   Lab Container       │
│  (Go 1.24 + tools)    │
│  hostveil --serve     │
│  http://localhost:9090 │
└──────────┬───────────┘
           │
┌──────────┴───────────┐
│ hostveil-lab bridge   │
├──────────────────────┤
│ vaultwarden:8081     │
│ jellyfin:8096        │
│ gitea:3000/2222      │
│ nextcloud:8082       │
│ nginx:8083           │
└──────────────────────┘
```

All targets have intentional issues (default creds, public ports, privileged mode, sensitive mounts, `:latest` tags) that hostveil flags.

---

## Running Tests

```sh
# All tests with race detection
go test -race -count=1 ./...

# Specific packages
go test -race -count=1 ./internal/scanner/...
go test -race -count=1 ./internal/adapter/...
go test -race -count=1 ./internal/fix/...
go test -race -count=1 ./internal/export/...
```

73+ tests across rule engine, host checks, adapters, fix engine, export, and TUI.

---

## Tech Stack

- **Language**: Go 1.24+, no CGO
- **TUI**: Bubbletea, Bubbles, Lipgloss, Glamour, Huh
- **YAML**: goccy/go-yaml
- **Web**: [ttyd](https://github.com/tsl0922/ttyd) — streams TUI via WebSocket
- **Build**: `go build`, cross-compile by `GOOS`/`GOARCH`
- **License**: GPL-3.0

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

hostveil is free software under the [GNU General Public License v3.0](LICENSE).

Copyright &copy; 2025-2026 Seol Kyu-won. See [LICENSE](LICENSE) for details.
