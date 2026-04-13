# AGENTS.md

Context for AI coding assistants (OpenCode, Cursor, etc.) working on this codebase.
Keep this file concise. It is not a substitute for README or docs — it covers what an AI needs to avoid bad decisions.

## What This Project Is

hostveil is a **lightweight TUI security dashboard for Linux self-hosted environments centered on Docker Compose deployments**.

The Python prototype validated the Compose parser, rule engine, scoring model, and fix flows. The real product direction is broader: native Compose checks, Linux host hardening checks, and optional external scanner adapters should all feed one scored self-hosting security tool. The long-term target audit axes are sensitive data exposure, excessive permissions, unnecessary exposure, update/supply-chain risk, and host hardening.

**Target users:** Self-hosters running services like Jellyfin, Vaultwarden, Gitea, Immich on a single Linux server.

## Tech Stack

| Phase | Language | Form | Timeline |
|---|---|---|---|
| Prototype | Python | CLI | Weeks 3–8 |
| Final product | Rust | TUI + JSON export | Weeks 8–14 |

- Python prototype lives in `proto/` — it is now a frozen reference implementation for Compose behavior
- Rust product lives in `src/` — all new product work should default here unless the user explicitly asks to touch `proto/`
- Runtime target: Linux only; Windows contributors should use WSL
- TUI stack: `ratatui` + `crossterm` (see `docs/adr/0003-tui-framework.md`)
- i18n: default output in English; Rust uses `rust-i18n` (see `docs/adr/0004-i18n-library.md`)

## Directory Layout

```
hostveil/
├── src/              # Rust product (active implementation target)
├── proto/            # Python CLI prototype (frozen reference)
├── docs/
│   └── adr/          # Architecture Decision Records — read before changing architecture
├── .github/
│   └── workflows/    # CI/CD (not yet set up)
├── AGENTS.md         # This file
├── CONTRIBUTING.md   # Git conventions, branch strategy, commit format
├── LICENSE           # GPLv3
└── README.md         # English-first; README.ko.md is the Korean version
```

## Conventions

**Git:**
- Branch prefixes: `feat/`, `fix/`, `docs/`, `refactor/`, `chore/`, `ci/`
- Commits: [Conventional Commits](https://www.conventionalcommits.org/) — `feat(scope): summary`, `fix: summary`, etc.
- No direct push to `main`; PRs required with 1 approval

**When to commit (for AI agents):**
- Commit after each **logical unit of work** is complete and the codebase is in a working state — not after every file save, and not only at the very end of a long task
- A logical unit is: one feature added, one bug fixed, one refactor done, one set of related docs updated
- Do **not** bundle unrelated changes into one commit — split them
- Do **not** commit a broken or half-finished state; if a task spans multiple commits, ensure each intermediate commit at least compiles/runs
- Prefer small, reviewable commits over large, hard-to-review ones
- Always run the relevant checks before committing: `cargo clippy && cargo fmt` (Rust), or verify the prototype runs (Python)

**i18n:**
- All user-visible strings must go through the i18n layer — no hardcoded display text
- English is the default locale

**Rust (when src/ exists):**
- `Cargo.lock` must be committed — hostveil is a binary crate
- Run `cargo clippy` and `cargo fmt` before committing

**Versioning and releases:**
- Use SemVer `X.Y.Z` for the crate and binary version
- Use annotated Git tags in the form `vX.Y.Z`
- Stay on `0.Y.Z` until the project is intentionally ready for `1.0.0`
- Treat version bumps as release work, not as routine feature work
- Keep `src/Cargo.toml`, `Cargo.lock`, and the release tag aligned

**Python (when proto/ exists):**
- Use a virtual environment; do not commit `.venv/`
- Follow the project's rule engine interface so logic ports cleanly to Rust

## GitHub Issues & Milestones

All planned work is tracked as GitHub Issues organized into 3 Milestones. **AI agents are expected to participate in this workflow without being told to do so.**

**Milestones** (see `github.com/seolcu/hostveil/milestones`):

| # | Title | Due |
|---|---|---|
| 1 | Python CLI Prototype | 2026-03-30 |
| 2 | Service Research & Rule Validation | 2026-04-19 |
| 3 | Rust TUI Implementation | 2026-05-31 |

**How AI agents should use Issues:**

- **Before starting work:** check if a matching Issue already exists (`gh issue list`). If it does, reference it. If the work is clearly scoped and not tracked yet, create an Issue before starting.
- **In commit messages:** always add `Closes #N` or `Refs #N` in the footer when a commit relates to an Issue. `Closes` auto-closes the Issue on merge; `Refs` links without closing.
- **In PRs:** link the relevant Issue(s) in the PR description. The PR title should follow Conventional Commits format.
- **When discovering untracked work:** create a new Issue with a clear title, a brief description, and a "Done when" checklist. Assign it to the correct Milestone.
- **Do not close Issues manually** — let `Closes #N` in merged commits do it automatically.

**Example commit footer:**
```
feat(proto/rules): add privileged container detection

Closes #4
```

## What NOT To Do

- Do not mix `proto/` (Python) and `src/` (Rust) logic
- Do not hardcode user-visible strings — always use the i18n layer
- Do not add `Cargo.lock` to `.gitignore`
- Do not commit `.env` files or any file containing credentials
- Do not create new documentation files speculatively; update existing ones
- Do not make architectural changes without checking `docs/adr/` first

## Key References

- `docs/adr/` — all major technical decisions with rationale
- `CONTRIBUTING.md` — full git workflow, commit rules, branch naming
- `README.md` — user-facing project overview
