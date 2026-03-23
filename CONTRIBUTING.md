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
cargo run -- --json --compose proto/tests/fixtures/parser/docker-compose.yml
cargo run -- --json --host-root /
```

The repository pins the shared Rust toolchain in `rust-toolchain.toml`.

## i18n

All user-facing strings must go through the i18n layer. Do not hardcode display strings in English or any other language directly. See `docs/adr/` for the chosen i18n approach.

## Code of Conduct

Be respectful and constructive. Focus on the work.
