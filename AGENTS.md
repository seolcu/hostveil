# AGENTS.md

Context for AI coding assistants working on this codebase.
Keep this concise — it is not a substitute for README or docs. It covers what an AI needs to avoid bad decisions.

## What This Project Is

hostveil is a lightweight TUI security dashboard for Linux self-hosted environments centered on Docker Compose deployments.

- Python prototype lives in `proto/` — frozen reference; do not modify unless explicitly asked
- Rust product crate at `src/Cargo.toml` with sources in `src/src/` (workspace root `Cargo.toml`, `members = ["src"]`, resolver "3")
- Runtime target: Linux only; Windows contributors should use WSL
- TUI stack: `ratatui 0.29` + `crossterm 0.29` (see `docs/adr/0003-tui-framework.md`)
- i18n: `rust-i18n 3` (crate `rust_i18n`, locale files `src/locales/en.yml` / `ko.yml`, fallback English) (see `docs/adr/0004-i18n-library.md`)
- Rust edition 2024 (pinned stable toolchain via `rust-toolchain.toml`)

## Non-Negotiable Rules

- **Do not mix `proto/` and `src/` logic.**
- **Do not hardcode user-visible strings.** All strings go through the i18n layer. English is the default locale.
- **`Cargo.lock` must be committed** — hostveil is a binary crate. Do not add it to `.gitignore`.
- **Do not commit `.env` files or any file containing credentials.**
- **Do not create new documentation files speculatively.** Update existing ones. Keep `README.md` and `README.ko.md` structures in sync.
- **Do not make architectural changes without checking `docs/adr/` first.**
- **After any architectural change, update the relevant ADR or create a new one.** Unmodified ADRs that contradict the codebase are treated as bugs.
- **Verify behavior, not just code.** After implementing a change, verify it works by running the relevant test or binary. Do not assume code compiles or works because it looks correct. Add TestBackend render tests for TUI changes that assert actual buffer cell content (colors, text, glyphs).

## TUI / Visual QA Rules

- TUI changes must include automated `TestBackend` render tests that inspect buffer cells.
- When changing styles, colours, or layout, assert on actual `Cell::style().fg` / `Cell::style().bg` values.
- Reuse helper functions `buffer_to_string`, `buffer_bg`, etc. (defined in `src/src/tui/mod.rs` tests, also duplicated in `src/src/tui/fix_review.rs`).
- When changing key bindings, update the help text, footer, and render tests together.
- Overview layout must show core information without scrolling in the default state. Use density-aware rendering (`ScoreDensity` modes) and `Min`-based constraints rather than fixed `Length()` values.
- **NEVER set `fg` on `Theme.highlight`**. In ratatui 0.29, `List.highlight_style.fg` applies at the cell level and completely overrides any span-level foreground colors. `Line::styled` or `Span::styled` are insufficient to preserve text colors on selected items when `highlight.fg` is set. The highlight background alone is sufficient for visual distinction.
- **Every finding-list render change must include a `TestBackend` test that asserts `Cell::fg` matches the expected severity color on a selected row.** The `selected_finding_preserves_severity_foreground_color` test in `src/src/tui/mod.rs` is the reference implementation.
- **Every keybinding change must include an E2E test that keystroke-simulates the key and asserts on both returned `TuiAction` and `state.screen`.** The `f_key_on_findings_does_not_change_screen_to_overview` test is the reference implementation.

## QA Testing Charter (Behavioral E2E Coverage)

Testing priority order (highest first):

1. **Fix engine pipeline**: Every `FixAction` variant (`ComposeEdit`, `HostEdit`, `ShellCommand`) must have unit tests that verify actual execution (file creation, content, permissions, shell command success/failure). The `execute_host_and_system_actions` function must be tested with all action combinations.

2. **Adapter classification coverage**: Every adapter (Dockle, Lynis) must have tests verifying each finding-to-`FixAction` mapping. Test both `Auto` and `Review` remediation paths, `Manual` skip behavior, unknown ID fallback, and unknown source filtering. The `multiple_findings_are_classified_independently` test in `src/src/fix/adapter.rs` must be kept up to date.

3. **External finding pipeline**: Adapter findings (Dockle, Lynis) from `ScanResult` must reach the fix engine. When a user presses `f` on an adapter finding, the `TuiAction::TriggerFix` must include `adapter_findings`. The `preview_with_external` / `apply_with_external` functions receive and classify these findings. Test that `host_actions` and `system_actions` in `FixPlan` are populated when adapter findings are present.

4. **E2E user-flow tests**: Use `TestBackend` with keystroke simulation (`KeyCode` arrays) to verify full user flows: settings toggle → UI reflects immediately, tab navigation, scroll behavior, border toggle → all panels update. Each flow test must assert on both state changes and buffer content.

5. **Fix review UI**: Every plan section (auto, review, host edit, shell command) must be rendered in `fix_review.rs`. Test that `host_actions` and `system_actions` summaries appear in the rendered output when present.

6. **Regression guard**: Run `cargo test --workspace` (must pass all 883+ tests) and `cargo clippy -D warnings` before every commit. Run `scripts/smoke-test.sh` and `scripts/test-install-script.sh` for release-impacting changes.

7. **Fix scenario tests**: Add scenarios to `tests/scenarios/<name>/` with `docker-compose.yml` + `expected.yml`. Run with `./scripts/verify-fixes.sh target/debug/hostveil`.

8. **CI mode in E2E scripts**: `CI_MODE=1 scripts/test-adapters-e2e.sh` must fail if required adapter binaries are missing, preventing silent skips in CI environments.

## Test Count Baseline

- **Workspace tests**: 883+ (lib: 883, main: 0, doc: 0)
- **Target coverage**: Adding tests is preferred over modifying existing ones. Each new feature or fix must add at minimum one behavioral E2E test that simulates real user interaction.

## Documentation Rules

- `README.md` and `README.ko.md` are user-facing: installation, quick start, usage, limitations.
- Developer details (build, labs, release policy, roadmap) belong in `CONTRIBUTING.md`.
- When editing one README, keep the other structurally aligned.
- Docker workflow docs should prefer the task-based `scripts/lab.sh` entrypoint; keep older script names working as compatibility paths.

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
- Do not commit `Cargo.lock` changes in feature PRs unless the PR is a dedicated release bump.
- Do not push directly to `main`.

## Key References

- `docs/adr/` — architecture decisions
- `CONTRIBUTING.md` — full developer workflow, commit conventions, release details
- `README.md` — user-facing overview
