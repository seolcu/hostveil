**[한국어](README.ko.md)** | English

# hostveil

> Lightweight, integrated security dashboard for self-hosted Docker Compose environments.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: Early Development](https://img.shields.io/badge/status-early%20development-orange)](https://github.com/seolcu/hostveil)

Self-hosters running Jellyfin, Nextcloud, Vaultwarden, Gitea, or Immich typically need to run and interpret several separate security tools — Lynis, Trivy, Dockle, Docker Bench — with results scattered across all of them. hostveil consolidates this into a single terminal dashboard: scored findings, prioritized by severity, each with a clear fix path.

Inspired by [Chrome Lighthouse](https://developer.chrome.com/docs/lighthouse/overview/) (scored audits with actionable guidance) and [btop](https://github.com/aristocratos/btop) (lightweight TUI design).

## Features

- **Security Overview Dashboard** — overall score with per-category breakdown and severity counts
- **Service-aware Rule Checks** — checks tailored to each service's known data locations and config structure
- **Actionable Guidance** — every finding includes: what it is, why it matters, how to fix it
- **quick-fix** — one-command auto-fix for safe, low-risk items
- **fix** — applies every available fix at once, including review-required guided changes, with preview, backup, and confirmation

## Audit Axes

| Axis | What it checks |
|---|---|
| Sensitive data exposure | `.env` files, plaintext/default credentials, secrets in volumes |
| Excessive permissions | `privileged: true`, root user, broad volume mounts, `network_mode: host` |
| Unnecessary exposure | Public ports, admin pages, services bypassing reverse proxy |
| Update/maintenance risk | `latest` image tags, missing version pins, outdated images |

## Installation

The final packaged binary is not available yet. The current working implementation is the Python prototype in `proto/`.

**Linux and macOS**

```sh
python3 -m venv proto/.venv
source proto/.venv/bin/activate
pip install -e "proto[dev]"
```

**Windows (PowerShell)** — from the repository root:

```powershell
python -m venv proto\.venv
.\proto\.venv\Scripts\Activate.ps1
pip install -e "proto[dev]"
```

If script execution is disabled, run PowerShell as Administrator once: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`, or use **Command Prompt** instead:

```bat
python -m venv proto\.venv
proto\.venv\Scripts\activate.bat
pip install -e "proto[dev]"
```

Use `py -m venv proto\.venv` if `python` is not on your `PATH` (Windows Python launcher).

## Usage

Run the prototype CLI against a Compose file or directory:

```sh
python -m hostveil scan path/to/docker-compose.yml
python -m hostveil quick-fix path/to/docker-compose.yml --preview-changes --yes
python -m hostveil fix path/to/docker-compose.yml --preview-changes --yes
```

## Status

hostveil is in active early development. The implementation is planned in two phases:

1. **Python CLI prototype** — rapid validation of the rule engine, scoring model, and Quick Fix logic
2. **Rust TUI** — lightweight, production-ready terminal dashboard ported from the validated prototype

Current prototype coverage:

- Docker Compose parsing with default override merging
- Four audit axes: sensitive data, permissions, exposure, and update risk
- Scoring model with severity counts and per-category safety scores
- Terminal scan report with `--no-color` support
- `quick-fix` flow with backup, preview-only diff (`--preview-changes`), and confirmation
- `fix` flow that combines safe fixes with review-required guided changes in one write to the compose file

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

hostveil is free software licensed under the [GNU General Public License v3.0](LICENSE).
