# ADR 0007: Compose-Only Remediation Boundary

**Date:** 2026-05-09
**Status:** Accepted

## Context

hostveil is a security dashboard for self-hosted operators, but its remediation features write configuration back to real systems.

That creates a safety problem: automatic fixes are valuable only when they stay reviewable, reversible, and narrowly scoped. The shipped Rust product already limits automatic writes to Docker Compose files and treats host findings as manual triage items.

## Decision

Rust v1 remediation stays Compose-focused only.

- `--auto-fix` applies automatic Compose changes only.
- `--fix` applies automatic Compose changes plus review-required Compose changes.
- Host findings remain detect-and-guide only.
- hostveil does not perform host-level auto-remediation in v1.

The active remediation kinds stay fixed to the shared domain model:

- `None`: informational/manual guidance only
- `Auto`: Compose edits hostveil can complete end-to-end after the diff review
- `Review`: Compose edits hostveil can drive, but only after the operator chooses an option or provides an input value

The implementation boundary is also fixed:

- remediation plans are built from findings tied to a Compose file
- writes target the Compose document, not host configuration files
- preview comes before apply
- apply creates a backup before writing
- reviewability of the diff preview is a first-class product constraint

## Why

- Keeps automatic writes within a file format the product already parses, normalizes, and tests thoroughly.
- Avoids mutating live host posture such as SSH, firewall, kernel, or MAC settings without explicit operator review outside the tool.
- Preserves the current TUI and CLI semantics, where host findings may explain what to change but do not claim `f` or `--fix` can safely do it for the operator.

## Consequences

- New remediation work should begin by asking whether the change still fits the Compose-only boundary; if not, it is a deliberate architecture expansion.
- Host findings must continue surfacing actionable guidance through `how_to_fix` and TUI context instead of through automatic writes.
- Fix UX work may improve previewing, filtering, and validation without changing the host-versus-Compose boundary.
- Any future host auto-remediation proposal requires a new ADR because it would change the product's safety model, not just add another fix rule.
