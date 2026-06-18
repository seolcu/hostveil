# Contributing to hostveil

This document covers the development setup, the TDD discipline,
the build and test scripts, and the release process for hostveil
v3.

## Dev setup

```bash
# 1. Clone and enter the repo
git clone https://github.com/seolcu/hostveil
cd hostveil

# 2. Confirm Go is available (>= 1.22)
go version

# 3. Run the test suite
make test-unit

# 4. Build the binary
make build
./dist/hostveil version
```

That's it — there is no node_modules, no venv, no Docker
required for the unit tests. The TUI / Web / AI integration
tests are stubbed at the unit level; the Docker-based
integration tests are gated by `HOSTVEIL_INTEGRATION=1`.

## TDD discipline

The project follows test-driven development. Per the constitution
(Principle III, Test-First NON-NEGOTIABLE):

1. Write the red test first. The test MUST be observed failing in
   CI before any production code lands.
2. Implement the minimum code to make the test green.
3. Refactor with the test as the safety net.

In practice, every task in `specs/001-selfhost-security/tasks.md`
that introduces a new package, function, or behavior comes with
a paired test task. The convention is `*_test.go` next to the
production file.

### Coverage

Run:

```bash
go test ./... -cover
```

The unit tests cover the foundational packages (model, store,
report, log, cli, fix, privilege) and the per-category scanners.
The integration tests cover end-to-end behavior against a
containerized test host.

## Build

```bash
make build              # default binary
make build-noai         # no AI code
make build-notui        # no TUI
make build-noweb        # no Web UI
make build-cross        # cross-compile to linux/{amd64,arm64,386,arm/v7}
```

The build is reproducible: `scripts/build.sh` embeds the git tag,
commit, and build date into the binary via `-ldflags`, and
records the SHA-256 of the produced binary for verification.

## Test

```bash
make test-unit         # unit tests only
make test-contract     # contract tests
make test-integration  # integration tests (needs Docker)
make test              # all of the above
```

The integration test suite is gated by `HOSTVEIL_INTEGRATION=1`;
without it, the integration tests are skipped. The performance
test suite is gated by `HOSTVEIL_PERF=1`.

## Release process

The release process for v3.0.0 is:

1. Ensure the working tree is clean: `git status`.
2. Tag the release: `git tag -a v3.0.0 -m "v3.0.0"`.
3. Push the tag: `git push origin v3.0.0`.
4. Run `make build-cross` to produce the linux/{amd64,arm64,386,arm/v7}
   binaries.
5. Run `make verify-noai` to confirm the noai build excludes all
   AI literals.
6. Run the full integration suite:
   `HOSTVEIL_INTEGRATION=1 make test`.
7. Sign the release artifacts with `scripts/release.sh` (post-v3.0).
8. Upload to the release tracker (post-v3.0).

For now, `scripts/release.sh` is a stub. The v3.0.0 release will
introduce the full script that tags, builds, signs, and attaches
artifacts.

## Layout

```
hostveil/
├── cmd/hostveil/             # Entry point
├── internal/
│   ├── cli/                  # cobra command tree
│   ├── scan/                 # orchestrator + fingerprint
│   ├── checks/               # per-category scanners
│   │   ├── ssh/
│   │   ├── docker/
│   │   ├── images/
│   │   ├── proxy/
│   │   ├── ssl/
│   │   └── hardening/
│   ├── cve/                  # CVE feed (v3.0.0: skeleton)
│   ├── fix/                  # apply / preview / backup / rollback
│   ├── report/               # text + JSON renderers
│   ├── store/                # SQLite state + migrations
│   ├── model/                 # 22 canonical entity types
│   ├── log/                   # slog setup
│   ├── version/              # build-time version
│   ├── platform/             # privilege, sysctl, package manager
│   ├── tui/                  # bubbletea TUI (v3.x)
│   ├── web/                  # localhost dashboard (v3.x)
│   └── ai/                   # AI layer (v3.x, gated by `noai` tag)
├── test/
│   ├── integration/          # end-to-end tests
│   ├── contract/             # public surface lock-in tests
│   └── hostimage/            # Dockerfile for the test host
├── scripts/                  # build, test, release
├── docs/                     # how-it-works, contributing
├── specs/                    # spec-kit artifacts
│   └── 001-selfhost-security/
│       ├── spec.md           # the spec
│       ├── plan.md           # the implementation plan
│       ├── research.md       # the research
│       ├── data-model.md     # the data model
│       ├── contracts/        # the contracts
│       ├── quickstart.md     # the quickstart
│       ├── checklists/       # the spec quality checklist
│       └── tasks.md          # the task breakdown
├── .specify/                 # spec-kit framework
├── .opencode/                # opencode CLI integration
├── .agents/                  # agent skills
├── LICENSE                   # GPL v3
├── README.md                 # top-level readme
├── CHANGELOG.md              # this file's sibling
├── Makefile                  # build / test / lint / verify-noai
├── go.mod
├── go.sum
├── .github/workflows/ci.yml  # CI
└── .gitignore
```

## Code style

- `gofmt` + `goimports` (enforced by `.golangci.yml`).
- Line length cap: 100 chars (`lll` linter).
- Test names: `TestXxx` for unit, `TestXxx_ForYyy` for
  sub-cases.
- Files: one type per file, named after the type in lower
  snake-case (`scanrun.go` contains `ScanRun`).
- Errors: wrap with `fmt.Errorf("...: %w", err)` so callers can
  use `errors.Is` / `errors.As`.
- Imports: stdlib first, then third-party, then the project
  (`goimports` will reorder for you).

## Reporting bugs

Open an issue on the upstream tracker. Include:

- The host's `go env GOOS GOARCH` and the binary's
  `hostveil version`.
- The exact `hostveil scan` invocation and its output.
- A redacted report file (the file is already redacted; remove
  any remaining sensitive info you see).

## Pull requests

1. Open a PR with a clear description of the change.
2. CI must pass (lint, unit, contract, integration, the
   `verify-noai` gate).
3. Add a CHANGELOG entry under "Unreleased" describing the change.
4. If the change adds a new scan rule, add a row to the
   `ruleExplanations` map in `internal/cli/explain.go` and a
   fixture to the relevant `internal/checks/<category>/`
   test file.
