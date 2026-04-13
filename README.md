**[한국어](README.ko.md)** | English

# hostveil

> Lightweight, integrated security dashboard for Linux self-hosted environments centered on Docker Compose.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: Early Development](https://img.shields.io/badge/status-early%20development-orange)](https://github.com/seolcu/hostveil)

Self-hosters running Jellyfin, Vaultwarden, Gitea, or Immich typically need to run and interpret several separate security tools — Lynis, Trivy, Dockle, Docker Bench, Fail2ban, and more — with results scattered across all of them. hostveil is intended to consolidate those signals into one terminal-first workflow: scored findings, prioritized by severity, explained in self-hosting terms, and paired with concrete fix guidance.

Inspired by [Chrome Lighthouse](https://developer.chrome.com/docs/lighthouse/overview/) (scored audits with actionable guidance) and [btop](https://github.com/aristocratos/btop) (lightweight TUI design).

## Features

- **Security Overview Dashboard** — overall score with per-category breakdown and severity counts
- **Native Self-hosting-aware Checks** — checks tailored to each service's known data locations, Compose structure, and operational risk
- **Optional External Scanner Adapters** — integrate existing tools without making them mandatory at runtime (Trivy is supported as an optional, recommended image vulnerability adapter)
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

Rust releases are delivered through GitHub Releases as Linux binaries. The Python prototype in `proto/` remains a frozen reference implementation for Compose parsing, scoring, and fix behavior while active product work continues in `src/`.

hostveil release tags follow `vX.Y.Z`, while the crate and binary version use `X.Y.Z`. Until compatibility is intentionally declared stable, releases stay on the `0.Y.Z` line instead of using prerelease suffixes.

Official runtime support for the real product is Linux. If you contribute from Windows, use WSL rather than native PowerShell.

Current Rust setup from the repository root:

```sh
rustup default stable
cargo build
cargo run -- --help
cargo run -- --version
cargo run
cargo run -- --json

# Advanced overrides for snapshots or targeted testing
cargo run -- --json --compose proto/tests/fixtures/parser/docker-compose.yml
cargo run -- --json --host-root /
cargo run -- --quick-fix proto/tests/fixtures/parser/docker-compose.yml --preview-changes
cargo run -- --fix proto/tests/fixtures/parser/docker-compose.yml --preview-changes

# Locale overrides (currently: en, ko)
HOSTVEIL_LOCALE=ko cargo run -- --help
LANG=ko_KR.UTF-8 cargo run -- --quick-fix proto/tests/fixtures/parser/docker-compose.yml --preview-changes
```

Container-based development and installer validation:

```sh
# Start the normal Rust dev container
./scripts/dev-env.sh up dev
./scripts/dev-env.sh shell dev

# Bring up distro-specific labs for setup validation
./scripts/dev-env.sh up fedora-lab ubuntu-lab debian-lab rocky-lab

# Exercise optional-tool setup inside a lab instead of on the host
./scripts/dev-env.sh setup fedora-lab lynis,trivy,fail2ban
./scripts/dev-env.sh setup ubuntu-lab lynis,trivy

# Run a host-root scan against the lab container itself
./scripts/dev-env.sh scan rocky-lab
```

The lab stack lives in `compose.dev.yml` and currently covers:

- `dev`: normal Rust development shell
- `fedora-lab`: Fedora + systemd + dnf validation
- `rocky-lab`: Rocky Linux + systemd + RHEL-like validation
- `ubuntu-lab`: Ubuntu + systemd + apt validation
- `debian-lab`: Debian + systemd + apt validation

The lab images share a generic `docker/labs/systemd-lab.Dockerfile`, so adding more distro services later should be a compose-level change instead of a full redesign.

Recent validation coverage for the live install and scan flows includes:

- local Fedora workstation validation for `hostveil setup --yes` and live host scans
- Ubuntu-based real server validation for `hostveil setup --yes --tools lynis,trivy` and follow-up live host scans
- containerized setup validation for Fedora, Ubuntu, Debian, and Rocky lab environments

Current reference prototype setup:

```sh
python3 -m venv proto/.venv
source proto/.venv/bin/activate
pip install -e "proto[dev]"
```

Current release delivery path:

- GitHub Releases tarballs for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`
- Published `SHA256SUMS` for release artifact verification
- A small install script that selects the correct Linux binary for the host architecture
- Optional external tools such as Lynis, Trivy, and Fail2Ban can be installed through a post-install setup flow instead of being bundled
- First-install bootstrap via installer script, then installed lifecycle commands for upgrade, launch-time auto-upgrade, and uninstall

Install the latest release:

```sh
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
```

After the first install, use the installed `hostveil` command for lifecycle actions.

If a terminal is available, the installer can also hand off to `hostveil setup` so you can install recommended optional tools such as Lynis, Trivy, and Fail2Ban right away.

Run the setup flow again later:

```sh
hostveil setup
```

For unattended installs, you can explicitly pick tools during bootstrap:

```sh
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash -s -- --with-tools lynis,trivy,fail2ban
```

Upgrade an existing installation to the latest available release:

```sh
hostveil upgrade
```

Automatic upgrades are enabled by default. Every `hostveil` launch checks the saved install metadata and upgrades before starting if a newer version is available.

Disable automatic upgrades:

```sh
hostveil auto-upgrade disable
```

Re-enable automatic upgrades:

```sh
hostveil auto-upgrade enable
```

Uninstall hostveil cleanly:

```sh
hostveil uninstall
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

Current Rust implementation status:

- Cargo workspace initialized at the repository root
- Active Rust crate scaffolded under `src/`
- Pinned stable toolchain via `rust-toolchain.toml`
- `ratatui` + `crossterm` TUI wired and localized through `rust-i18n`
- Generalized Rust scan result model and minimal JSON export path working
- Compose parser ported with override merging and normalization parity tests
- Native Compose rule engine and scoring model ported with Rust fixture tests
- Native Linux host checks added for SSH posture, Docker host exposure, and defensive-control telemetry via `--host-root`
- Optional Trivy image and Lynis host adapters integrated into the shared findings pipeline
- Initial Rust Compose remediation flow added for previewable `--quick-fix` and `--fix` operations with backup-safe writes
- No-arg live scan now defaults to host scanning plus Docker-based Compose auto-discovery, with current-directory Compose fallback

## Release Policy

hostveil release versions follow standard SemVer without suffixes: `X.Y.Z` for the crate and binary, and `vX.Y.Z` for Git tags.

- Stay on `0.Y.Z` until the project is intentionally ready for `1.0.0`
- Bump patch for backward-compatible fixes, install/update flow fixes, and shipped polish
- Bump minor for new user-visible features, command surface changes, and materially expanded rule or adapter coverage
- Reserve `1.0.0` for the point where compatibility expectations become intentionally stable
- Do not bump versions in every PR; version changes should land as dedicated release work
- Create GitHub Releases only from annotated `vX.Y.Z` tags pushed from `main`
- The release tag must match `src/Cargo.toml` and `Cargo.lock`

Current release priorities:

- Linux-only scope with clear known limitations
- Native Compose and host checks through one shared scan result
- TUI overview plus finding detail navigation for real scan results
- Minimal headless JSON export for automation and regression snapshots
- Previewable Compose `--quick-fix` and `--fix` flows with backup-safe writes
- Release artifacts published through GitHub Releases with checksums
- An install script for first install plus installed lifecycle commands for later upgrades
- Core smoke-test coverage for the supported CLI entry points before publishing

Explicitly deferred from the current early-release scope:

- Additional optional adapters beyond Trivy, Lynis, and Dockle
- TUI-embedded guided diff review before writes
- Package-manager distribution such as apt, dnf, Homebrew, or AUR
- Final scoring ADR and stable weighting guarantees

Optional dependency policy for current releases:

- `hostveil` should install and run without Docker, Trivy, Dockle, or Lynis being present
- Docker-based live discovery improves Compose coverage when available
- Trivy and Dockle remain optional image adapters; if either is missing, scans continue with reduced coverage instead of failing
- Lynis remains an optional host adapter; if it is missing, scans continue with reduced host-audit coverage instead of failing
- Missing external tools should be shown as coverage or adapter status, not as fatal startup errors

Planned install and update model for current releases:

- Install from GitHub Releases rather than from a package manager
- Download a single architecture-specific Linux binary archive
- Verify the archive against `SHA256SUMS`
- Install to a standard user or system binary path such as `~/.local/bin` or `/usr/local/bin`
- Track install metadata so launch-time auto-upgrade and installed `hostveil upgrade` / `hostveil uninstall` actions work cleanly

Release gates:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- Smoke tests for `hostveil`, `hostveil --json`, targeted Compose scans, targeted host scans, and preview-only fix flows
- Release notes that document supported platforms, optional dependencies, and known limitations

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

hostveil is free software licensed under the [GNU General Public License v3.0](LICENSE).
