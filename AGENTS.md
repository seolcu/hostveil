# AGENTS.md

Context for AI coding assistants working on this codebase.
Keep this concise — it is not a substitute for README or docs. It covers what an AI needs to avoid bad decisions.

## What This Project Is

hostveil is a lightweight TUI security dashboard for Linux self-hosted environments centered on Docker Compose deployments.

- Python prototype lives in `proto/` — frozen reference; do not modify unless explicitly asked
- Rust product lives in `src/` — all new product work defaults here
- Runtime target: Linux only; Windows contributors should use WSL
- TUI stack: `ratatui` + `crossterm` (see `docs/adr/0003-tui-framework.md`)
- i18n: `rust-i18n` with English default (see `docs/adr/0004-i18n-library.md`)

## Non-Negotiable Rules

- **Do not mix `proto/` and `src/` logic.**
- **Do not hardcode user-visible strings.** All strings go through the i18n layer. English is the default locale.
- **`Cargo.lock` must be committed** — hostveil is a binary crate. Do not add it to `.gitignore`.
- **Do not commit `.env` files or any file containing credentials.**
- **Do not create new documentation files speculatively.** Update existing ones. Keep `README.md` and `README.ko.md` structures in sync.
- **Do not make architectural changes without checking `docs/adr/` first.**

## TUI / Visual QA Rules

- TUI changes must include automated `TestBackend` render tests that inspect buffer cells.
- When changing styles, colours, or layout, assert on actual `Cell::style().fg` / `Cell::style().bg` values.
- Reuse helper functions `buffer_to_string`, `buffer_bg`, etc. from `src/tui/mod.rs` tests.
- When changing key bindings, update the help text, footer, and render tests together.
- Overview layout must show core information without scrolling in the default state. Use density-aware rendering (`ScoreDensity` modes) and `Min`-based constraints rather than fixed `Length()` values.

## Documentation Rules

- `README.md` and `README.ko.md` are user-facing: installation, quick start, usage, limitations.
- Developer details (build, labs, release policy, roadmap) belong in `CONTRIBUTING.md`.
- When editing one README, keep the other structurally aligned.

## GitHub Issues & Milestones

- Before starting work, check if a matching Issue exists (`gh issue list`). Reference it. If not, create one.
- In commits, add `Closes #N` or `Refs #N` in the footer.
- In PRs, link the Issue and use Conventional Commits format for the PR title.
- Do not close Issues manually — let merged commits auto-close them.
- Treat version bumps as release work, not routine feature work.

## Versioning and Releases

- SemVer `X.Y.Z` for crate and binary; annotated Git tags `vX.Y.Z`.
- Stay on `0.Y.Z` until intentionally ready for `1.0.0`.
- Keep `src/Cargo.toml`, `Cargo.lock`, and the release tag aligned.
- Release commits should use `chore(release): bump version to vX.Y.Z`.

## When to Commit

- Commit after each logical unit of work is complete and the codebase is in a working state.
- Do not bundle unrelated changes.
- Do not commit a broken or half-finished state; each intermediate commit must at least compile and pass tests.
- Run the relevant checks before committing:
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace`
  - For install/release/entrypoint-impacting changes, also run `./scripts/smoke-test.sh target/debug/hostveil` and `./scripts/test-install-script.sh target/debug/hostveil`.

## What NOT To Do

- Do not modify `proto/` unless explicitly asked.
- Do not bypass the i18n layer.
- Do not commit `Cargo.lock` changes in feature PRs unless the PR is a dedicated release bump.
- Do not push directly to `main`.

## Key References

- `docs/adr/` — architecture decisions
- `CONTRIBUTING.md` — full developer workflow, commit conventions, release details
- `README.md` — user-facing overview
