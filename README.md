**[한국어](README.ko.md)** | English

# hostveil

> Lightweight, integrated security dashboard for Linux self-hosted environments centered on Docker Compose.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellowgreen)](https://github.com/seolcu/hostveil)

Self-hosters running Jellyfin, Nextcloud, Vaultwarden, Gitea, or Immich typically need to run and interpret several separate security tools — Lynis, Trivy, Dockle, Gitleaks, Fail2ban, and more — with results scattered across all of them. hostveil is intended to consolidate those signals into one terminal-first workflow: scored findings, prioritized by severity, explained in self-hosting terms, and paired with concrete fix guidance.

## Features

- **Security Overview Dashboard** — responsive overview with overall posture, per-axis breakdown, grouped action queue, adapter activity, and selectable layouts
- **Native Self-hosting-aware Checks** — checks tailored to each service's known data locations, Compose structure, and operational risk
- **Optional External Scanner Adapters** — integrate existing tools without making them mandatory at runtime (Trivy, Dockle, Lynis, and Gitleaks are supported as optional adapters)
- **Visible Background Progress** — launch-time auto-upgrade checks and in-TUI adapter loading surface status instead of appearing frozen
- **Settings Modal** — change theme, layout, and locale from the TUI with keyboard or mouse controls
- **Theme Presets** — terminal-default ANSI plus Catppuccin, Nord, Tokyo Night, Gruvbox, Dracula, Monokai, Light, and Solarized Light presets are available from the TUI
- **Actionable Guidance** — every finding includes: what it is, why it matters, how to fix it
- **Guided Remediation Workflow** — previewable, backup-safe Compose changes plus reviewed host-level actions from supported adapters

## Installation

hostveil is distributed through GitHub Releases as Linux tarballs and package assets.

```sh
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
```

The installer selects the correct architecture (`x86_64` or `aarch64`) and installs to `~/.local/bin` or `/usr/local/bin`. After installation, use the `hostveil` command directly.

If a terminal is available, the installer can hand off to `hostveil setup` so you can install recommended optional tools such as Lynis, Trivy, Dockle, Gitleaks, and Fail2Ban right away.

Package installs are also available for Debian users and for Fedora-family or Rocky/RHEL 9-class users:

```sh
sudo apt install ./hostveil_<version>_amd64.deb
sudo dnf install ./hostveil-<version>-1.x86_64.rpm
```

RPM packages are built on a Rocky Linux 9 compatible baseline. Package installs use your system package manager for upgrades and removal instead of hostveil's launch-time auto-upgrade flow.

Run the setup flow again later:

```sh
hostveil setup
```

Upgrade an existing installation:

```sh
hostveil upgrade
```

For package installs, download a newer release package and install it with `apt` or `dnf` instead of using `hostveil upgrade`.

Disable or re-enable automatic upgrades:

```sh
hostveil auto-upgrade disable
hostveil auto-upgrade enable
```

Package installs do not support launch-time auto-upgrade.

Uninstall cleanly:

```sh
hostveil uninstall
```

For package installs, remove hostveil with your system package manager, for example `sudo apt remove hostveil` or `sudo dnf remove hostveil`.

> **Note:** Lifecycle commands (`upgrade`, `uninstall`, `auto-upgrade`) behave differently by install mode. `install.sh` installs use the bundled wrapper, while package installs return package-manager guidance.

## Quick Start

Run hostveil interactively:

```sh
hostveil
```

Run a headless JSON scan:

```sh
hostveil --json
hostveil --compose path/to/docker-compose.yml --json
hostveil --host-root / --json
hostveil --json --adapters none
hostveil --json --findings-only
```

Generate a shareable or automation-friendly headless report:

```sh
hostveil --markdown
hostveil --html
hostveil --sarif
```

Use Markdown or HTML for human-readable sharing, and JSON or SARIF for automation and downstream tooling.

Use `--findings-only` with `--json` to emit only the findings array for lightweight downstream processing.

Optional scanner adapters default to `all`. Use `--adapters none` for native-only scans, or choose a subset such as `--adapters trivy,dockle,gitleaks`.

Locale defaults to English for terminal safety. Use `hostveil --locale ko ...` or `HOSTVEIL_LOCALE=ko hostveil ...` for Korean. In the TUI, open Settings (`s`) to switch locale and persist it.

## Usage

### TUI Controls

- `1` / `2` / `3` — switch between Overview, Findings, and History
- `Enter` — open Findings from the overview
- `s` — open Settings (theme, layout, locale)
- `t` — open History trend view
- `/` — open findings search
- `?` — show help overlay
- `Tab` — cycle focus between overview panels
- `L` — cycle layout preset
- Mouse — click tabs, findings rows, and settings rows
- `q` or `Esc` — quit or go back

### Overview

- **Security Scores** — overall posture score and per-axis breakdown (Sensitive Data, Permissions, Exposure, Updates, Host Hardening)
- **Scan Results** — summary of findings by service, severity counts, and adapter status
- **Action Queue** — grouped next-step summary by service or host scope, separating auto-fixable and manual items
- **History** — score and finding-count trends across recent scans (press `t` from the overview)
- While adapters are still running, the score panel shows progress and keeps the native baseline visible

### Findings View

- Browse findings by severity with filters for source, remediation type, and service
- Each finding shows evidence, risk explanation, and concrete fix guidance
- Press `f` on a fixable finding to open the remediation flow

### Fix Workflow

Preview Compose remediation before writing files:

```sh
hostveil --auto-fix path/to/docker-compose.yml --preview-changes
hostveil --fix path/to/docker-compose.yml --preview-changes
```

- `--auto-fix` applies changes that hostveil can complete end-to-end without extra input
- `--fix` combines automatic changes with review-required changes that may ask you to choose an option or provide a value
- `Auto` means `f` can carry the change all the way through after the diff review
- `Review` means `f` can still drive the remediation flow, but hostveil needs your choice or input before it can build the final patch
- `Manual` is reserved for findings hostveil cannot realistically change for you, such as physical or external infrastructure actions
- Both create backups before writing

## Optional Tools

hostveil runs without optional dependencies, but coverage improves when they are present:

| Tool | Role | Install |
|------|------|---------|
| Lynis | Host security audit | `hostveil setup` or system package manager |
| Trivy | Image vulnerability scan | `hostveil setup` or system package manager |
| Dockle | Image best-practice scan | `hostveil setup` on supported Linux targets, manual fallback otherwise |
| Gitleaks | Project secret leak scan | `hostveil setup` on supported Linux `x86_64` / `aarch64`, manual fallback otherwise |
| Fail2Ban | Intrusion prevention | `hostveil setup` or system package manager |

Use `--adapters none` to skip all external scanners, or `--adapters trivy,dockle,gitleaks` to run a subset.

## Target Audit Axes

| Axis | What it checks |
|------|----------------|
| Sensitive data exposure | `.env` files, plaintext/default credentials, secrets in volumes |
| Excessive permissions | `privileged: true`, root user, broad volume mounts, `network_mode: host` |
| Unnecessary exposure | Public ports, admin pages, services bypassing reverse proxy |
| Update/supply chain risk | `latest` image tags, missing version pins, outdated images |
| Host hardening | SSH posture, Docker host exposure, firewall, defensive controls |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, lab workflows, git workflow, testing, and release information.

## License

hostveil is free software licensed under the [GNU General Public License v3.0](LICENSE).
