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

| Type | Use when |
|---|---|
| `feat` | Adding new functionality |
| `fix` | Fixing a bug |
| `docs` | Documentation changes only |
| `refactor` | Code restructuring without behavior change |
| `test` | Adding or updating tests |
| `chore` | Build process, tooling, dependency updates |
| `ci` | CI/CD configuration |

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

## i18n

All user-facing strings must go through the i18n layer. Do not hardcode display strings in English or any other language directly. See `docs/adr/` for the chosen i18n approach.

## Code of Conduct

Be respectful and constructive. Focus on the work.
