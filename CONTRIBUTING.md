# hostveil Contribution Guide

Thank you for your interest in hostveil. This document provides the information needed to contribute to the project.

## Project Overview

hostveil is a TUI dashboard that audits security configurations in Linux self-hosting environments. It is written in Go 1.24+ with Bubbletea and automatically scans Docker Compose stacks and host environments.

See [AGENTS.md](AGENTS.md) for implementation details and architecture.

## Development Setup

- **Go 1.24+** is required. Verify with `go version`.
- Docker Compose V2 is required (for the lab environment).

```sh
# Clone the repository
git clone https://github.com/seolcu/hostveil.git
cd hostveil

# Build
go build -o hostveil ./cmd/hostveil/

# Start the Docker Lab environment (optional)
./scripts/lab.sh up
```

## Code Style

- Format code with `gofmt`.
- `go vet ./...` must produce no warnings.
- If `golangci-lint` is configured, passing it is recommended.
- Prefer clear variable names and consistent naming over unnecessary comments.

## Running Tests

```sh
# Full test suite (with race detection)
go test -race -count=1 ./...

# Test a specific package
go test -race -count=1 ./internal/scanner/...
go test -race -count=1 ./internal/adapter/...
go test -race -count=1 ./internal/fix/...
go test -race -count=1 ./internal/export/...
```

Write related tests when adding new features.

## Branch Strategy (GitHub Flow)

1. Create a feature branch from `main`.
2. Use branch prefixes: `feat/`, `fix/`, `docs/`, `refactor/`, `chore/`.
3. Submit a Pull Request to `main` when work is complete.
4. Merge after approval from at least 1 reviewer.
5. Direct pushes to `main` are blocked.

## Commit Message Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <concise description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`
Summary line: 72 characters max, imperative mood.

## Pull Request Process

- PR titles should follow Conventional Commits format.
- Ensure all related tests pass before submitting.
- For UI changes, include screenshots or a description.
- Keep dependency changes out of the PR scope unless necessary.

## Code of Conduct

Respect others and communicate constructively. Discrimination, harassment, and abuse are not tolerated.
