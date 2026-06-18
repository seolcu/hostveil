<!--
Sync Impact Report (constitution v1.0.0)
=========================================
- Version change: 0.0.0 (unmodified template) → 1.0.0
- Modified principles: none (initial ratification; all five principles are new)
- Added sections:
  * Core Principles (I–V)
  * Additional Constraints
  * Development Workflow
  * Governance
- Removed sections: none (template placeholders were replaced in place)
- Templates requiring updates:
  ✅ .specify/templates/plan-template.md     — no change required; the "Constitution Check" gate is generic and is filled by /speckit.plan from this file
  ✅ .specify/templates/spec-template.md     — no change required; structure is constitution-agnostic
  ✅ .specify/templates/tasks-template.md    — no change required; existing test-first ordering already aligns with Principle III
  ✅ .specify/templates/checklist-template.md — no change required; structure is constitution-agnostic
  ✅ .opencode/commands/*.md                 — no change required; no agent-specific (e.g. CLAUDE-only) references introduced. The CLAUDE.md / copilot-instructions.md mention in speckit.agent-context.update.md is an example list, not a CLAUDE-only requirement.
- Follow-up TODOs: none (project context was insufficient for tech-stack specifics; the constitution is intentionally technology-agnostic at this layer)
-->

# hostveil Constitution

## Core Principles

### I. Library-First

Every feature in hostveil MUST begin as a self-contained library within the
project's package layout. A library MUST be independently importable,
independently testable, and MUST ship with documentation that describes
its purpose, public API, and intended usage. Libraries that exist solely
for organizational grouping — without a concrete capability — are
forbidden: every library MUST justify its existence with a real,
documented behavior.

### II. CLI-First Interface

Every library and core capability MUST expose its functionality through a
command-line entry point that follows a strict text in/out contract:
arguments and stdin supply input, stdout emits results, and stderr
carries diagnostics and errors. Each command MUST support at least one
machine-readable output format (JSON) in addition to any human-readable
format, so that every feature is scriptable, debuggable, and
automatable from shell pipelines and CI.

### III. Test-First (NON-NEGOTIABLE)

Test-Driven Development is mandatory for hostveil. Tests MUST be written
and reviewed BEFORE any production code that satisfies them. The
Red-Green-Refactor cycle is strictly enforced: a failing test MUST be
observed before the implementation is added, and no production change
is accepted without a corresponding test or a documented, time-boxed
justification for its absence.

### IV. Integration Testing

Unit tests alone are insufficient for hostveil. Integration tests MUST
exercise real interactions between components. Mandatory integration
test surfaces include: new library contracts, changes to existing
contracts, inter-process or inter-service communication, and any code
that touches shared schemas or persistent state. Integration tests
MUST be runnable in isolation and in CI without manual setup beyond
documented, version-pinned prerequisites.

### V. Observability & Versioning

All hostveil processes MUST emit structured, machine-parseable logs that
include a timestamp, severity, source component, and, when available,
a correlation identifier. Behavior that affects data, security, or
external contracts MUST be observable end-to-end. Public interfaces and
data formats MUST follow semantic versioning: MAJOR for incompatible
changes, MINOR for backward-compatible additions, PATCH for fixes.
Breaking changes MUST be recorded in the changelog and accompanied by
a migration note.

## Additional Constraints

These cross-cutting constraints apply to every feature and dependency
decision in hostveil, in addition to the Core Principles above.

- **Privacy by default**: features MUST minimize the collection,
  retention, and exposure of user data. Persistent state MUST be
  opt-in, narrowly scoped, and clearly documented.
- **Local-first execution**: capabilities SHOULD run without network
  access unless networking is the explicit purpose of the feature.
  Outbound network calls MUST be opt-in and disclosed in documentation.
- **Deterministic builds**: builds MUST be reproducible from version
  control. Lockfiles and commit hashes MUST be honored by the build
  pipeline; a clean checkout MUST produce identical artifacts.
- **No ambient telemetry**: any outbound call for diagnostics or
  analytics MUST be explicitly opt-in. hostveil MUST NOT phone home
  silently under any circumstance.

## Development Workflow

hostveil uses a quality-gated workflow. Every change MUST pass through
the following stages in order; no stage may be skipped.

1. **Specification**: the feature MUST be captured in `specs/` with
   prioritized user stories, acceptance criteria, and measurable
   success criteria.
2. **Plan**: an implementation plan MUST identify the technical
   approach, dependencies, the resulting project structure, and a
   Constitution Check that confirms alignment with this document.
3. **Tasks**: the plan MUST be decomposed into tasks organized by user
   story, with parallelizable work marked `[P]` and a clearly stated
   execution order.
4. **Review**: code changes MUST be reviewed against this constitution
   and the relevant spec, plan, and tasks before merge. Reviewers MUST
   verify that tests exist, that the Constitution Check is satisfied,
   and that no principle is violated without explicit justification.
5. **Validation**: automated tests, lint, and any project-defined
   static checks MUST pass before a change is considered mergeable.
   The Constitution Check MUST be re-evaluated after design work is
   complete.

## Governance

This constitution supersedes all other practices, conventions, and
guidance within hostveil. Where any other document conflicts with this
constitution, the constitution wins until the conflict is resolved by
a formal amendment.

- **Amendments**: any change to this constitution MUST be proposed as a
  pull request that includes the proposed text, the rationale, and a
  migration plan when the amendment affects existing work. Amendments
  require approval from a project maintainer and MUST be merged with a
  Sync Impact Report recorded at the top of this file.
- **Versioning policy**: this constitution follows semantic versioning.
  MAJOR bumps denote backward-incompatible governance or principle
  changes; MINOR bumps add new principles or materially expand
  guidance; PATCH bumps are clarifications, typo fixes, and other
  non-semantic refinements.
- **Compliance review**: every spec, plan, and pull request MUST be
  checked against the current constitution. A "Constitution Check"
  section MUST be present in every `plan.md`, MUST pass before
  implementation work begins, and MUST be re-checked after design
  work is complete.
- **Runtime guidance**: project-specific runtime and contribution
  guidance lives in `AGENTS.md` (managed coding-agent context) and
  repository documentation. Runtime guidance MUST NOT contradict this
  constitution; the constitution is the source of truth for project
  principles.

**Version**: 1.0.0 | **Ratified**: 2026-06-18 | **Last Amended**: 2026-06-18
