**[한국어](README.ko.md)** | English

# hostveil

> Lightweight, integrated security dashboard for Linux self-hosted environments centered on Docker Compose.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: Early Development](https://img.shields.io/badge/status-early%20development-orange)](https://github.com/seolcu/hostveil)

Self-hosters running Jellyfin, Nextcloud, Vaultwarden, Gitea, or Immich typically need to run and interpret several separate security tools — Lynis, Trivy, Dockle, Docker Bench, Fail2ban, and more — with results scattered across all of them. hostveil is intended to consolidate those signals into one terminal-first workflow: scored findings, prioritized by severity, explained in self-hosting terms, and paired with concrete fix guidance.

Inspired by [Chrome Lighthouse](https://developer.chrome.com/docs/lighthouse/overview/) (scored audits with actionable guidance) and [btop](https://github.com/aristocratos/btop) (lightweight TUI design).

## Features

- **Security Overview Dashboard** — responsive overview with overall posture, per-axis breakdown, grouped action queue, adapter activity, and selectable layouts
- **Native Self-hosting-aware Checks** — checks tailored to each service's known data locations, Compose structure, and operational risk
- **Optional External Scanner Adapters** — integrate existing tools without making them mandatory at runtime (Trivy, Dockle, and Lynis are supported as optional adapters)
- **Visible Background Progress** — launch-time auto-upgrade checks and in-TUI adapter loading surface status instead of appearing frozen
- **Settings Modal** — change theme, layout, and locale from the TUI with keyboard or mouse controls
- **Theme Presets** — terminal-default ANSI plus Catppuccin, Nord, Tokyo Night, Gruvbox, Dracula, Monokai, Light, and Solarized Light presets are available from the TUI
- **Actionable Guidance** — every finding includes: what it is, why it matters, how to fix it
- **Compose-focused Remediation** — `quick-fix` and `fix` stay focused on previewable, backup-safe Compose changes

## Rust V1 Direction

- **Linux-first runtime** — the product officially targets Linux self-hosted servers; Windows contributors should use WSL for development
- **Integration-first** — hostveil should combine native Compose and host checks with optional scanner results instead of reimplementing every existing tool
- **TUI-first with JSON export** — the main experience is interactive, but a small headless JSON path exists for automation and regression tests
- **Host checks are first-class** — SSH and other host-hardening signals belong in the same product, not in a separate side tool
- **Safe remediation stays narrow in v1** — automatic writes remain limited to Compose-focused changes with clear review boundaries

## Target Audit Axes

| Axis                     | What it checks                                                                  |
| ------------------------ | ------------------------------------------------------------------------------- |
| Sensitive data exposure  | `.env` files, plaintext/default credentials, secrets in volumes                 |
| Excessive permissions    | `privileged: true`, root user, broad volume mounts, `network_mode: host`        |
| Unnecessary exposure     | Public ports, admin pages, services bypassing reverse proxy                     |
| Update/supply chain risk | `latest` image tags, missing version pins, outdated images, image trust signals |
| Host hardening           | SSH posture, Docker host exposure, and defensive controls on the server itself  |

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
cargo run -- --json --adapters none

# Advanced overrides for snapshots or targeted testing
cargo run -- --json --compose proto/tests/fixtures/parser/docker-compose.yml
cargo run -- --json --host-root /
HOSTVEIL_ADAPTERS=trivy,dockle cargo run -- --json
cargo run -- --quick-fix proto/tests/fixtures/parser/docker-compose.yml --preview-changes
cargo run -- --fix proto/tests/fixtures/parser/docker-compose.yml --preview-changes

# Locale overrides (currently: en, ko)
HOSTVEIL_LOCALE=ko cargo run -- --help
cargo run -- --locale ko --quick-fix proto/tests/fixtures/parser/docker-compose.yml --preview-changes
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
- Optional external tools are not bundled; post-install setup can install Lynis, Trivy, and Fail2Ban from package repositories and can surface Dockle's manual install path
- First-install bootstrap via installer script, then installed lifecycle commands for upgrade, launch-time auto-upgrade, and uninstall

Install the latest release:

```sh
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
```

After the first install, use the installed `hostveil` command for lifecycle actions.

Lifecycle commands are wrapper-managed by design. Running development binaries directly (for example, `cargo run -- upgrade` or `target/debug/hostveil upgrade`) does not perform install-state changes, and instead returns a guidance error: `upgrade is only available through the installed hostveil wrapper. Install first with: curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash, then run: hostveil upgrade`.

If a terminal is available, the installer can also hand off to `hostveil setup` so you can install recommended optional tools such as Lynis, Trivy, and Fail2Ban right away.

Run the setup flow again later:

```sh
hostveil setup
```

Locale defaults to English for terminal safety, even if the host locale is non-English. Use `hostveil --locale ko ...` or `HOSTVEIL_LOCALE=ko hostveil ...` for an explicit override. In the TUI, open Settings (`s`) to switch locale and persist it.

When automatic upgrade checks run through the installed wrapper, hostveil now prints a short launch-time status line so slow update checks are visible instead of feeling like a hang.

Interactive setup explains the selector controls before input starts, and its confirmation prompts use a default-yes `Y/n` flow.

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

Run the Rust product interactively or as a headless JSON scan:

```sh
hostveil
hostveil --json
hostveil --compose path/to/docker-compose.yml --json
hostveil --host-root / --json
hostveil --json --adapters none
HOSTVEIL_ADAPTERS=trivy,dockle hostveil --json
```

Optional scanner adapters default to `all`. Use `--adapters none` for native-only scans, or choose a subset such as `--adapters trivy,dockle`.

Current TUI controls:

- `Enter` opens Findings from the overview
- `s` opens Settings (theme, layout, locale)
- `L` cycles the layout preset (overview)
- `f` opens the remediation flow when Compose fixes are available

Current overview model:

- `Security Scores` shows the final score when adapter loading is complete
- while adapters are still running, the score panel shows adapter progress and keeps the native baseline explicit
- `Action Queue` is a grouped next-step summary by service or host scope
- `Findings` is the per-issue drill-down view with evidence, risk explanation, and fix detail

Preview Compose remediation before writing files:

```sh
hostveil --quick-fix path/to/docker-compose.yml --preview-changes
hostveil --fix path/to/docker-compose.yml --preview-changes
```

Run installed lifecycle and setup commands:

```sh
hostveil setup
hostveil upgrade
hostveil auto-upgrade disable
hostveil uninstall
```

Lifecycle commands are intentionally available through the installed wrapper path. If you run an uninstalled development binary directly, `upgrade`, `uninstall`, and `auto-upgrade` return guidance (e.g., `upgrade is only available through the installed hostveil wrapper...`) instead of mutating install state.

The Python CLI in `proto/` remains a frozen reference implementation. Use it only when comparing or validating historical prototype behavior.

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
- Responsive overview and findings layouts with persisted Adaptive, Wide, Balanced, Compact, and Focus presets
- Scrollable overview/finding panels, tabbed navigation, and mouse hit targets mirror keyboard workflows
- TUI findings navigation supports remediation-first triage for faster review of fixable issues
- Explicit locale controls are available through `--locale`, `HOSTVEIL_LOCALE`, and the in-TUI Settings modal (`s`)
- Persisted TUI theme presets with ANSI, Catppuccin, Nord, Tokyo Night, Gruvbox, Dracula, Monokai, Light, and Solarized Light palettes
- Generalized Rust scan result model and minimal JSON export path working
- Compose parser ported with override merging and normalization parity tests
- Native Compose rule engine and scoring model ported with Rust fixture tests
- Native Linux host checks added for SSH posture, Docker host exposure, and defensive-control telemetry via `--host-root`
- Optional Trivy, Dockle, and Lynis adapters integrated into the shared findings pipeline
- Per-adapter background progress is surfaced in the TUI while external coverage is still loading
- Non-root live host scans skip Lynis instead of invoking desktop authorization prompts
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

v0.10.0 release highlights:

- TUI layout presets are user-selectable and covered by a render matrix across representative terminal sizes
- Visible TUI security content wraps instead of relying on ellipsis-style truncation
- Overview and Findings panels support scrolling with visible scrollbars where content overflows
- Settings modal exposes theme, layout, and locale controls through localized keyboard and mouse workflows
- Tab navigation and precise mouse hit targets make Overview, Findings, and Settings more discoverable

Current release priorities:

- Linux-only scope with clear known limitations
- Native Compose and host checks through one shared scan result
- TUI overview plus finding detail navigation for real scan results
- Explicit locale control with English-by-default terminal behavior and in-TUI language switching
- Minimal headless JSON export for automation and regression snapshots
- Previewable Compose `--quick-fix` and `--fix` flows with backup-safe writes
- Release artifacts published through GitHub Releases with checksums
- An install script for first install plus installed lifecycle commands for later upgrades
- Core smoke-test coverage for the supported CLI entry points before publishing

Explicitly deferred from the current early-release scope:

- Additional optional adapters beyond Trivy, Lynis, and Dockle
- Package-manager distribution such as apt, dnf, Homebrew, or AUR
- Stable scoring-weight guarantees across future releases

Optional dependency policy for current releases:

- `hostveil` should install and run without Docker, Trivy, Dockle, or Lynis being present
- Docker-based live discovery improves Compose coverage when available
- Optional scanner execution can be controlled with `--adapters` or `HOSTVEIL_ADAPTERS`
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
- Installer lifecycle tests for install, upgrade, auto-upgrade, custom state directories, setup handoff, and uninstall
- Release notes that document supported platforms, optional dependencies, and known limitations

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

hostveil is free software licensed under the [GNU General Public License v3.0](LICENSE).
