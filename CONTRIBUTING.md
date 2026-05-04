# Contributing to hostveil

Thank you for your interest in contributing to hostveil!

## Git Workflow

We use **GitHub Flow**:

1. Create a branch from `main` with the appropriate prefix (see below)
2. Make focused, atomic commits following the commit convention
3. Open a pull request against `main`
4. Get at least one approval from a team member
5. Merge — squash if the branch has noisy intermediate commits

Direct pushes to `main` are blocked. All changes go through pull requests.

### Branch Naming

```
feat/<short-description>      # New feature
fix/<short-description>       # Bug fix
docs/<short-description>      # Documentation only
refactor/<short-description>  # Refactoring without behavior change
chore/<short-description>     # Build, tooling, dependency updates
ci/<short-description>        # CI/CD configuration
```

Examples: `feat/privileged-container-check`, `fix/scoring-weight-overflow`, `docs/installation-instructions`

## Commit Messages

We follow **[Conventional Commits](https://www.conventionalcommits.org/)**:

```
<type>(<optional scope>): <short summary in imperative mood>

[optional body: explain the why, not the what]

[optional footer: breaking changes, issue refs]
```

### Types

| Type       | Use when                                   |
| ---------- | ------------------------------------------ |
| `feat`     | Adding new functionality                   |
| `fix`      | Fixing a bug                               |
| `docs`     | Documentation changes only                 |
| `refactor` | Code restructuring without behavior change |
| `test`     | Adding or updating tests                   |
| `chore`    | Build process, tooling, dependency updates |
| `ci`       | CI/CD configuration                        |

### Examples

```
feat(rules): add detection for privileged container flag
fix(scoring): correct weight calculation for critical findings
docs: add installation instructions to README
chore: add .gitignore for Rust and Python
refactor(proto): extract rule engine into separate module
```

### Rules

- Summary line: 72 characters max, imperative mood ("add" not "added", "fix" not "fixed")
- Do not end the summary line with a period
- Body is optional but encouraged for non-trivial changes

## Versioning And Releases

We use **Semantic Versioning** for shipped versions.

- Package and binary version format: `X.Y.Z`
- Git tag format: `vX.Y.Z`
- Do not use `-alpha`, `-beta`, or other prerelease suffixes in normal release tags
- Until the project declares stable compatibility, stay on the `0.Y.Z` line instead of jumping to `1.0.0`

### How To Bump Versions

- Bump **patch** (`0.4.2` -> `0.4.3`) for bug fixes, install/update flow fixes, reliability improvements, and other backward-compatible polish
- Bump **minor** (`0.4.2` -> `0.5.0`) for new user-visible features, new commands, new rule coverage, or materially expanded functionality
- Bump **major** (`1.4.2` -> `2.0.0`) only for intentional breaking compatibility changes after `1.0.0`
- Use `1.0.0` only when the project is ready to treat CLI behavior, release policy, and compatibility expectations as stable

### When To Bump Versions

- Do **not** bump the version in every feature PR
- Bump the version only in a dedicated release change when `main` is ready to ship
- Keep `src/Cargo.toml` and `Cargo.lock` aligned in the same change
- Release commits should use a dedicated message such as `chore(release): bump version to v0.5.0`

### When Releases Happen

- Create a GitHub Release only from `main`
- Release only when there is a meaningful shipped change since the previous tag
- Docs-only changes normally ship with the next code release instead of triggering a standalone release
- After the release change is merged, create and push an annotated tag `vX.Y.Z` from that `main` commit
- The tag push is the only thing that should trigger the release workflow
- The pushed tag must match the version in `src/Cargo.toml`

### Validation Matrix

Use this matrix to understand which gates run in CI versus tag-based release validation.

| Context             | Workflow                                                  | Required checks                                                                                                                                                                                                                                                                                                 |
| ------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Push / Pull Request | `.github/workflows/rust-ci.yml`                           | `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo build --workspace`, `./scripts/smoke-test.sh target/debug/hostveil`, `./scripts/test-install-script.sh target/debug/hostveil`, `cargo-tarpaulin` coverage report (artifact)          |
| Tag push (`vX.Y.Z`) | `.github/workflows/rust-release.yml` (validate job)       | tag-version match (`src/Cargo.toml`), `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo build --release --workspace`, `./scripts/smoke-test.sh target/release/hostveil`, `./scripts/test-install-script.sh target/release/hostveil` |
| Tag push (`vX.Y.Z`) | `.github/workflows/rust-release.yml` (build/release jobs) | cross-target release build (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`), artifact packaging, `SHA256SUMS`, GitHub Release publish                                                                                                                                                                  |

### Coverage Policy

CI generates an HTML/Lcov coverage report on every push and pull request via `cargo-tarpaulin`. The report is uploaded as a build artifact named `coverage-report`.

- Coverage measurement is informational for now. There is no hard threshold gate that blocks merges.
- When adding new user-visible features or host checks, include tests that exercise the new code path. PR reviews will check whether the changed modules improved or regressed coverage.
- If you notice a module with near-zero coverage, open a follow-up issue so it can be prioritized.
- Coverage artifacts are kept per-workflow-run and can be downloaded from the GitHub Actions summary page.

Locale note for shell-based smoke assertions:

- Smoke and installer tests are designed to run deterministically with English default output unless a test explicitly overrides locale.

## Development Setup

The product is now entering the Rust implementation phase.

### Python Prototype (`proto/`)

The Python prototype is a frozen reference implementation. Use it to confirm parser, scoring, and fix behavior; do not treat it as the main delivery target unless a task explicitly says otherwise.

```sh
python3 -m venv proto/.venv
source proto/.venv/bin/activate
pip install -e "proto[dev]"

# Run the prototype CLI
python -m hostveil scan path/to/docker-compose.yml

# Run tests
pytest
```

### Rust TUI (`src/`)

Official runtime support is **Linux only**.

If you contribute from Windows, use **WSL** (Ubuntu recommended) instead of native PowerShell. The goal is one shared Linux-like Rust workflow for the team.

From the repository root:

```sh
rustup default stable

cargo build
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test

# Run the current Rust binary
cargo run -- --help
cargo run
cargo run -- --json

# Advanced overrides for targeted snapshots or fixtures
cargo run -- --json --compose proto/tests/fixtures/parser/docker-compose.yml
cargo run -- --json --host-root /
```

The repository pins the shared Rust toolchain in `rust-toolchain.toml`.

### Development Containers and Labs

The repository provides containerized environments for safe testing without polluting the host or requiring host-level sudo.

**`compose.dev.yml`** — Multi-distro lab:

- `dev` service: Rust development container with writable workspace
- Distro labs (`fedora-lab`, `rocky-lab`, `ubuntu-lab`, `debian-lab`): systemd-based containers for testing `hostveil setup` and host scans across distributions

Managed via `scripts/dev-env.sh`:

```sh
# Start dev container
./scripts/dev-env.sh up dev
./scripts/dev-env.sh shell dev

# Start a distro lab
./scripts/dev-env.sh up fedora-lab
./scripts/dev-env.sh setup ubuntu-lab lynis,trivy
./scripts/dev-env.sh scan rocky-lab
./scripts/dev-env.sh down
```

**`docker-compose.lab.yml`** — Web TUI observation:

- `lab` service: ttyd-based container exposing hostveil TUI on `http://localhost:7681`
- `vulnerable-service`: nginx with intentional misconfigurations for scanning

**Self-hosting lab** — managed by `scripts/self-hosting-lab.sh`:

```sh
# Start a realistic self-hosting lab with intentionally vulnerable services
./scripts/self-hosting-lab.sh up
./scripts/self-hosting-lab.sh shell
./scripts/self-hosting-lab.sh check
./scripts/self-hosting-lab.sh reset
```

The lab stack spins up misconfigured Vaultwarden, Jellyfin, Gitea, Nextcloud, PostgreSQL, and nginx services so Compose parsing, scoring, fix previews, and TUI behavior can be exercised without copying development builds to a real server.

For safety, the helper script rewrites public port bindings to `127.0.0.1` before starting the lab services. The original Compose file keeps literal `0.0.0.0` bindings so hostveil still reports them as findings.

## i18n

All user-facing strings must go through the i18n layer. Do not hardcode display strings in English or any other language directly. See `docs/adr/` for the chosen i18n approach.

## Fix Verification Scenarios

End-to-end remediation scenarios live in `tests/scenarios/<name>/`.

Each scenario needs:
- `docker-compose.yml` — the vulnerable input
- `expected.yml` — the expected file after `--fix`
- `expected-quick-fix.yml` (optional) — the expected file after `--quick-fix` when it differs from `--fix`

Add a scenario when you introduce a new safe or guided Compose fix. Run the full suite with:

```sh
./scripts/verify-fixes.sh target/debug/hostveil
```

## Project Status and Roadmap

hostveil is in active early development. The implementation is planned in two phases:

1. **Python CLI prototype** — completed reference for the Compose parser, core rules, scoring, and safe fix flows
2. **Rust TUI** — active implementation of the real product

### Rust V1 Direction

- **Linux-first runtime** — the product officially targets Linux self-hosted servers; Windows contributors should use WSL for development
- **Integration-first** — hostveil should combine native Compose and host checks with optional scanner results instead of reimplementing every existing tool
- **TUI-first with JSON export** — the main experience is interactive, but a small headless JSON path exists for automation and regression tests
- **Host checks are first-class** — SSH and other host-hardening signals belong in the same product, not in a separate side tool
- **Safe remediation stays narrow in v1** — automatic writes remain limited to Compose-focused changes with clear review boundaries

### Current Implementation Status

- Cargo workspace initialized at the repository root
- Active Rust crate scaffolded under `src/`
- Pinned stable toolchain via `rust-toolchain.toml`
- `ratatui` + `crossterm` TUI wired and localized through `rust-i18n`
- Responsive overview and findings layouts with persisted Adaptive, Wide, Balanced, Compact, and Focus presets
- Scrollable overview/finding panels, tabbed navigation, and mouse hit targets mirror keyboard workflows
- Explicit locale controls available through `--locale`, `HOSTVEIL_LOCALE`, and the in-TUI Settings modal (`s`)
- Persisted TUI theme presets with ANSI, Catppuccin, Nord, Tokyo Night, Gruvbox, Dracula, Monokai, Light, and Solarized Light palettes
- Generalized Rust scan result model and minimal JSON export path working
- Compose parser ported with override merging and normalization parity tests
- Native Compose rule engine and scoring model ported with Rust fixture tests
- Native Linux host checks added for SSH posture, Docker host exposure, kernel sysctl hardening, SELinux/AppArmor status, and defensive-control telemetry via `--host-root`
- Optional Trivy, Dockle, and Lynis adapters integrated into the shared findings pipeline
- Per-adapter background progress surfaced in the TUI while external coverage is still loading
- Non-root live host scans skip Lynis instead of invoking desktop authorization prompts
- Initial Rust Compose remediation flow added for previewable `--quick-fix` and `--fix` operations with backup-safe writes
- No-arg live scan now defaults to host scanning plus Docker-based Compose auto-discovery, with current-directory Compose fallback
- Service-aware Compose checks expanded to Traefik, Portainer, Home Assistant, Pi-hole, Grafana, Caddy, GitLab, Uptime Kuma, PostgreSQL, MySQL, Redis, Duplicati, Restic, Borg, and Kopia in addition to Vaultwarden, Jellyfin, Gitea, Immich, and Nextcloud

### Deferred from Current Early-Release Scope

- Additional optional adapters beyond Trivy, Lynis, and Dockle
- Package-manager distribution such as apt, dnf, Homebrew, or AUR
- Stable scoring-weight guarantees across future releases

## Code of Conduct

Be respectful and constructive. Focus on the work.
