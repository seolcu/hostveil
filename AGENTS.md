# AGENTS.md

Context for AI coding assistants on this repo. Not a substitute for README or docs — covers what you'd likely get wrong without help.

## Project Structure

- **Single crate** at `src/Cargo.toml`, workspace root `Cargo.toml` (`members = ["src"]`, resolver "3"). Source in `src/src/`, binary entrypoint `src/src/main.rs`, library root `src/src/lib.rs`.
- **Rust edition 2024**, pinned stable toolchain (`rust-toolchain.toml`). Linux-only target.
- **15 public modules** (14 always + `web` behind `#[cfg(feature = "web")]`): `adapters`, `app`, `compose`, `discovery`, `domain`, `export`, `fix`, `history`, `host`, `i18n`, `rules`, `scoring`, `settings`, `tui`.
- `proto/` is a frozen Python prototype — **never modify** unless explicitly asked.

## Web Feature (Optional)

The `web` feature (`cargo build --features web`) adds an **axum 0.8** web server behind `--serve`:
- Enable: `hostveil --serve [--port 8080] [--host 127.0.0.1]`
- `src/src/web/` module tree: `mod.rs` → `server.rs` + `state.rs` + `api/` (7 endpoints) + `pages/` (5 HTML handlers).
- Uses HTMX + server-rendered HTML fragments. No JS build step.
- Feature-gated: default binary is unchanged. All web deps (axum, tokio, tower, tower-http) are optional.

## Key Architecture

- **Single `ScanResult` contract** (ADR 0006): all findings, scores, metadata flow through one canonical type in `domain/mod.rs`.
- **TUI is primary interface**: `ratatui 0.29` + `crossterm 0.29` (ADR 0003).
- **All user-visible strings go through `rust-i18n 3`** (crate `rust_i18n`, locale files `src/locales/en.yml`/`ko.yml`, fallback English). Never hardcode strings.
- **Fix engine** (`src/src/fix/`): `preview()`/`apply()` variants for compose edits, host edits, shell commands. Adapter findings route through `preview_with_external`/`apply_with_external`.
- **Locale resolution order**: `--locale` flag → `HOSTVEIL_LOCALE` env var → saved setting → system default (fallback `en`). TUI Settings modal (`s`) persists locale.
- **Key TUI shortcuts**: `s` settings, `l` layout cycle, `?` help, `h` host-filtered findings, `/` search, `q` quit, `Tab`/`t` cycle panel focus.

## Development

- **Primary dev entrypoint**: `./scripts/lab.sh dev shell` — wrapped dev container with writable workspace. Multi-distro host labs via `./scripts/lab.sh host up <distro>`.
- **Requires `docker-compose.yml`** in CWD or explicitly via `--compose <path>`. Use `--host-root /` for host-level scans, `cargo run -- --json --host-root /` for headless JSON output.
- **Fix scenarios** at `tests/scenarios/<name>/`: each has `docker-compose.yml` + `expected.yml`. After modifying fix flows, validate with `./scripts/verify-fixes.sh target/debug/hostveil`.
- **Non-root live scans skip Lynis** automatically (avoids sudo prompts). External adapters (Trivy, Dockle, Lynis, Gitleaks) are optional.

## Install & Run

```sh
# Default TUI (requires docker-compose.yml in cwd or --compose):
cargo run

# Web interface (optional feature):
cargo run --features web -- --serve

# Output modes: --json, --sarif, --markdown, --html
# Privilege escalation: auto via sudo unless --user-mode or --serve
```

## Test & Verify

Commands in this order (CI enforces them):
```sh
cargo fmt --check                                  # format
cargo clippy --workspace --all-targets --all-features -- -D warnings  # lint
cargo test --workspace                             # 883+ tests (lib), none in main/doc
./scripts/smoke-test.sh target/debug/hostveil       # integration (release: s/release/debug)
./scripts/test-install-script.sh target/debug/hostveil  # installer smoke
```

TUI changes require `TestBackend` render tests asserting `Cell::style().fg`/`Cell::style().bg`. Never set `fg` on `Theme.highlight` (see `selected_finding_preserves_severity_foreground_color` test).

## Commit & Branch Rules

- **Branch naming**: `feat/<desc>`, `fix/<desc>`, `docs/<desc>`, `refactor/<desc>`, `chore/<desc>`, `ci/<desc>`.
- Conventional Commits (`feat:`, `fix:`, `chore:`, etc.), 72-char summary max.
- Do not commit `Cargo.lock` unless it's a dedicated release bump.
- Do not push directly to `main`; use PRs against `main`.
- Squash noisy intermediate commits on merge.
- Tagged releases use annotated tags `vX.Y.Z` on `0.Y.Z` line until `1.0.0`.

## What NOT To Do

- Do not modify `proto/` unless explicitly asked.
- Do not create new documentation files speculatively.
- Do not hardcode user-visible strings (i18n layer exists).
- Do not make architectural changes without reading `docs/adr/` first — unmodified ADRs that contradict code are bugs.
- Do not commit `.env` files or credentials.

## Key References

- `docs/adr/` — 9 architecture decisions (TUI framework, i18n, scoring, adapter fix engine, etc.)
- `CONTRIBUTING.md` — full commit conventions, release workflow, lab environment details
- `README.md` / `README.ko.md` — user-facing (keep in sync when editing either)
- `.github/workflows/` — CI pipeline (fmt → clippy → test → smoke → packages → coverage)
