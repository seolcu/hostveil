# hostveil

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)

> **hostveil** — Linux self-hosting security dashboard. Zero-config, terminal-native, adapter-aware.

Inspired by Chrome Lighthouse and `btop`, hostveil scans your Docker Compose stacks and host environment for security misconfigurations — then presents everything in one interactive TUI. Just run `hostveil`.

---

## Quick Start

```sh
# Interactive TUI (auto-discovers everything)
hostveil

# Restricted privileges (skip host-level checks)
hostveil --user-mode
```

Just `hostveil`. It finds compose files, runs rules, detects adapter tools, and opens a TUI with dashboard, findings, and report screens.

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
| **Service-Aware** | 23 known services with tailored checks (Vaultwarden, Jellyfin, Gitea, Nextcloud, Immich, Traefik, Portainer, Home Assistant, Pi-hole, Grafana, Nginx Proxy Manager, Caddy, Authentik, Paperless, PostgreSQL, MySQL/MariaDB, Redis, GitLab, Uptime Kuma, Duplicati, Restic, Borg, Kopia) |

### Host Auditing — 9 Check Modules

| Module | What It Checks |
|--------|---------------|
| **SSH** | PermitRootLogin, password auth, protocol version |
| **Docker** | Daemon socket exposure, daemon TLS |
| **Firewall** | Active firewall (iptables/nftables/ufw), default policies |
| **Kernel** | Kernel updates, core dumps, IP forwarding |
| **Filesystem** | World-writable files, SUID binaries, separate partitions |
| **FIM** | File integrity monitoring (AIDE) |
| **MAC** | Mandatory access control (AppArmor, SELinux) |
| **Defenses** | Fail2ban, rkhunter, auditd |
| **Updates** | Unattended-upgrades, pending reboot |

### External Adapters — Installed = Auto-Run

| Adapter | Purpose |
|---------|---------|
| **Trivy** | Container image vulnerability scanning |
| **Dockle** | Docker image best-practices linter |
| **Lynis** | Host-level security auditing |
| **Gitleaks** | Git secret/credential leak detection |

No config needed. Available tools are auto-detected via PATH and their results merge into the findings list.

### Fix Engine

Guided remediation for compose files and host configs:

- **Preview** changes before applying (press `p` on any fixable finding).
- **Auto** — applied on confirm (pin tags, drop caps, bind ports).
- **Review** — user input needed (reverse proxy, Vaultwarden config).
- **Manual** — instructions provided when automation isn't possible.
- **Backups** — original files are backed up before edits.
- **Host + adapter fixes** — shell commands for SSH, firewall, Trivy updates, Gitleaks cleanup.

### Export

Available from the Report screen:

| Format | Use Case |
|--------|----------|
| **JSON** | Machine-readable, pipeline integration |
| **SARIF** | Static analysis interchange (SIEM, CodeQL) |
| **Markdown** | Human-readable reports, PR comments |
| **HTML** | Rich formatted reports for stakeholders |

### TUI Themes

5 themes: Tokyo Night, Dracula, Nord, Catppuccin, Gruvbox. Press `s` on the Dashboard or Report screen to change themes.

---

## Installation

### GitHub Releases (recommended)

```sh
curl -fsSL https://github.com/seolcu/hostveil/releases/latest/download/hostveil_linux_amd64 -o /usr/local/bin/hostveil
chmod +x /usr/local/bin/hostveil
```

Architectures: `amd64`, `arm64`. Linux only.

### Go Install

```sh
go install github.com/seolcu/hostveil/cmd/hostveil@latest
```

Requires Go 1.24+.

---

## Build from Source

Go 1.24+, no CGO.

```sh
git clone https://github.com/seolcu/hostveil.git
cd hostveil
go build -o hostveil ./cmd/hostveil/

# Cross-compile (native, no toolchain)
GOOS=linux GOARCH=arm64 go build -o hostveil-linux-arm64 ./cmd/hostveil/
```

Or use Makefile: `make build`, `make cross`, `make test`.

---

## Usage

### TUI Screens

| Key | Screen | Content |
|-----|--------|---------|
| `1` | **Dashboard** | Score card, axis breakdown, action queue, adapter status, host info |
| `2` | **Findings** | Severity-sorted list, detail panel, fix preview, filters, search |
| `3` | **Report** | Score summary, severity breakdown, export options |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1` / `2` / `3` | Switch screens (Dashboard / Findings / Report) |
| `↑` / `↓` or `j` / `k` | Move selection |
| `Enter` or `l` | Open detail / select |
| `Esc` or `h` | Back / close panel |
| `/` | Search findings |
| `f` | Open filter panel (Findings) |
| `s` | Cycle sort (Findings) / Open settings (Dashboard/Report) |
| `p` | Toggle fix preview (on fixable findings) |
| `a` | Apply fix (from fix preview) |
| `h` | Host triage — filter findings to host scope (Dashboard) |
| `r` | Reset filters (Findings) / Reset export cursor (Report) |
| `?` | Toggle help overlay |
| `q` | Quit |

### Findings Screen

- Sorted by severity by default (Critical → High → Medium → Low).
- Filter by source, scope, service, or remediation type.
- Three sort modes: severity, source, title.
- Press `p` on fixable findings to preview the diff before applying.
- Press `a` to apply after preview.

### Fix Engine Workflow

1. Select a fixable finding (`Auto` or `Review` type).
2. Press `p` — preview panel shows the diff and action summary.
3. Press `a` to apply — engine backs up the original file and applies the fix.

### Export

From Report screen, use `j`/`k` to select format and `Enter` to export. Creates `hostveil_report_<timestamp>.<format>` in the current directory.

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

Complete lab environment for development and testing. Spins up a scanner container with all tools pre-installed plus several intentionally-vulnerable compose stacks.

### Prerequisites

Docker (Compose V2), Git.

### Setup

```sh
cd hostveil
./scripts/lab.sh up
```

Builds the lab container (Go 1.24, Trivy, Dockle, Lynis, Gitleaks) and starts Vaultwarden, Jellyfin, Gitea, Nextcloud, and nginx — each with deliberate security flaws.

### Lab Commands

```sh
./scripts/lab.sh up              # Start lab (scanner + all targets)
./scripts/lab.sh down            # Stop all lab services
./scripts/lab.sh shell           # Enter lab container (bash)
./scripts/lab.sh run             # Run hostveil inside lab (auto-discovery)
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
│  hostveil             │
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
- **TUI**: Bubbletea, Bubbles, Lipgloss
- **YAML**: goccy/go-yaml
- **Build**: `go build`, cross-compile by `GOOS`/`GOARCH`
- **License**: GPL-3.0

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines. See [AGENTS.md](AGENTS.md) for implementation details and architecture.

## License

hostveil is free software under the [GNU General Public License v3.0](LICENSE).

Copyright &copy; 2025-2026 Seol Kyu-won. See [LICENSE](LICENSE) for details.
