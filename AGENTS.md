# AGENTS.md

Context for AI coding assistants (OpenCode, Cursor, etc.) working on this codebase.
Keep this file concise. It is not a substitute for README or docs — it covers what an AI needs to avoid bad decisions.

## What This Project Is

hostveil is a **lightweight TUI security dashboard for self-hosted Docker Compose environments**.

It audits Docker Compose setups across four axes: sensitive data exposure, excessive permissions, unnecessary external exposure, and update/maintenance risk. Results are scored like Chrome Lighthouse: prioritized by severity, each finding paired with an explanation and a fix path. The prototype currently offers a safe `quick-fix` flow and a broader `fix` flow that can also apply review-required guided changes after preview and confirmation.

**Target users:** Self-hosters running services like Jellyfin, Nextcloud, Vaultwarden, Gitea, Immich on a single Linux server.

## Tech Stack

| Phase | Language | Form | Timeline |
|---|---|---|---|
| Prototype | Python | CLI | Weeks 3–8 |
| Final product | Rust | TUI | Weeks 8–14 |

- Python prototype lives in `proto/` — its purpose is to validate rule logic before committing to Rust
- Rust TUI lives in `src/` — TUI framework is likely `ratatui` (not yet decided; check `docs/adr/`)
- i18n: default output in English; user-configurable locale (library TBD; check `docs/adr/`)

## Directory Layout

```
hostveil/
├── src/              # Rust TUI (not yet started)
├── proto/            # Python CLI prototype (active implementation)
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

**Python (when proto/ exists):**
- Use a virtual environment; do not commit `.venv/`
- Follow the project's rule engine interface so logic ports cleanly to Rust

## GitHub Issues & Milestones

All planned work is tracked as GitHub Issues organized into 4 Milestones. **AI agents are expected to participate in this workflow without being told to do so.**

**Milestones** (see `github.com/seolcu/hostveil/milestones`):

| # | Title | Due |
|---|---|---|
| 1 | Python CLI Prototype | 2026-03-30 |
| 2 | Service Research & Rule Validation | 2026-04-19 |
| 3 | Rust TUI Implementation | 2026-05-31 |
| 4 | Finalization & Submission | 2026-06-21 |

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
