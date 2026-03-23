**[한국어](README.ko.md)** | English

# hostveil

> Lightweight, integrated security dashboard for Linux self-hosted environments centered on Docker Compose.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: Early Development](https://img.shields.io/badge/status-early%20development-orange)](https://github.com/seolcu/hostveil)

Self-hosters running Jellyfin, Nextcloud, Vaultwarden, Gitea, or Immich typically need to run and interpret several separate security tools — Lynis, Trivy, Dockle, Docker Bench, Fail2ban, CrowdSec, and more — with results scattered across all of them. hostveil is intended to consolidate those signals into one terminal-first workflow: scored findings, prioritized by severity, explained in self-hosting terms, and paired with concrete fix guidance.

Inspired by [Chrome Lighthouse](https://developer.chrome.com/docs/lighthouse/overview/) (scored audits with actionable guidance) and [btop](https://github.com/aristocratos/btop) (lightweight TUI design).

## Features

- **Security Overview Dashboard** — overall score with per-category breakdown and severity counts
- **Native Self-hosting-aware Checks** — checks tailored to each service's known data locations, Compose structure, and operational risk
- **Optional External Scanner Adapters** — integrate existing tools without making them mandatory at runtime
- **Actionable Guidance** — every finding includes: what it is, why it matters, how to fix it
- **Compose-focused Remediation** — `quick-fix` and `fix` stay focused on previewable, backup-safe Compose changes

## Rust V1 Direction

- **Linux-first runtime** — the product officially targets Linux self-hosted servers; Windows contributors should use WSL for development
- **Integration-first** — hostveil should combine native Compose and host checks with optional scanner results instead of reimplementing every existing tool
- **TUI-first with JSON export** — the main experience is interactive, but a small headless JSON path exists for automation and regression tests
- **Host checks are first-class** — SSH and other host-hardening signals belong in the same product, not in a separate side tool
- **Safe remediation stays narrow in v1** — automatic writes remain limited to Compose-focused changes with clear review boundaries

## Target Audit Axes

| Axis | What it checks |
|---|---|
| Sensitive data exposure | `.env` files, plaintext/default credentials, secrets in volumes |
| Excessive permissions | `privileged: true`, root user, broad volume mounts, `network_mode: host` |
| Unnecessary exposure | Public ports, admin pages, services bypassing reverse proxy |
| Update/supply chain risk | `latest` image tags, missing version pins, outdated images, image trust signals |
| Host hardening | SSH posture, Docker host exposure, and defensive controls on the server itself |

## Installation

The final packaged Rust binary is not available yet. The Python prototype in `proto/` is now a frozen reference implementation for Compose parsing, scoring, and fix behavior while active product work moves into `src/`.

Official runtime support for the real product is Linux. If you contribute from Windows, use WSL rather than native PowerShell.

Current Rust bootstrap setup from the repository root:

```sh
rustup default stable
cargo build
cargo run -- --help
cargo run -- --json --compose proto/tests/fixtures/parser/docker-compose.yml
cargo run -- --json --host-root /
```

Current reference prototype setup:

```sh
python3 -m venv proto/.venv
source proto/.venv/bin/activate
pip install -e "proto[dev]"
```

## Usage

Run the frozen prototype CLI against a Compose file or directory:

```sh
python -m hostveil scan path/to/docker-compose.yml
python -m hostveil quick-fix path/to/docker-compose.yml --preview-changes --yes
python -m hostveil fix path/to/docker-compose.yml --preview-changes --yes
```

## Status

hostveil is in active early development. The implementation is planned in two phases:

1. **Python CLI prototype** — completed reference for the Compose parser, core rules, scoring, and safe fix flows
2. **Rust TUI** — active implementation of the real product

Validated reference from the prototype:

- Docker Compose parsing with default override merging
- Four audit axes: sensitive data, permissions, exposure, and update risk
- Scoring model with severity counts and per-category safety scores
- Terminal scan report with ANSI styling (disable with `NO_COLOR` in the environment)
- `quick-fix` flow with backup, preview-only diff (`--preview-changes`), and confirmation
- `fix` flow that combines safe fixes with review-required guided changes in one write to the compose file

Planned Rust v1 scope:

- Generalized findings across service, host, image, and project contexts
- Five target axes, including Host Hardening
- Native Linux host checks for SSH and Docker-host posture
- Optional external adapters, starting with Trivy
- TUI-first workflow plus minimal headless JSON export
- Linux-only runtime support with contributor setup documented for WSL

Current Rust bootstrap status:

- Cargo workspace initialized at the repository root
- Active Rust crate scaffolded under `src/`
- Pinned stable toolchain via `rust-toolchain.toml`
- `ratatui` + `crossterm` TUI bootstrap wired and localized through `rust-i18n`
- Generalized Rust scan result model and minimal JSON export path working
- Compose parser ported with override merging and normalization parity tests
- Native Compose rule engine and scoring model partially ported with Rust fixture tests
- Native Linux host checks started for SSH posture and Docker host exposure via `--host-root`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

hostveil is free software licensed under the [GNU General Public License v3.0](LICENSE).
