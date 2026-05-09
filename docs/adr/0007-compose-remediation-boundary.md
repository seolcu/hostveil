# ADR 0007: Compose-Only Remediation Boundary

**Date:** 2026-05-09
**Status:** Accepted

## Context

hostveil is a security dashboard for self-hosted operators, but its remediation features write configuration back to real systems.

That creates a safety problem: automatic fixes are valuable only when they stay reviewable, reversible, and narrowly scoped. By the May 13 design review, the shipped Rust product already limits automatic writes to Docker Compose files and treats host findings as manual triage items.

The remediation boundary needs to be frozen before the presentation so the product is evaluated against its intended safety model rather than against an implied "auto-harden the whole server" scope.

## Decision

Rust v1 remediation stays Compose-focused only.

- `--quick-fix` applies safe Compose changes only.
- `--fix` applies safe Compose changes plus guided Compose changes.
- Host findings remain detect-and-guide only.
- hostveil does not perform host-level auto-remediation in v1.

The active remediation kinds stay fixed to the shared domain model:

- `None`: informational/manual guidance only
- `Safe`: low-risk Compose edits that can be applied automatically
- `Guided`: reviewable Compose edits that are still machine-generated but intentionally narrower than "rewrite the stack"

The implementation boundary is also fixed:

- remediation plans are built from findings tied to a Compose file
- writes target the Compose document, not host configuration files
- preview comes before apply
- apply creates a backup before writing
- reviewability of the diff preview is a first-class product constraint

## Why

- Keeps automatic writes within a file format the product already parses, normalizes, and tests thoroughly.
- Avoids mutating live host posture such as SSH, firewall, kernel, or MAC settings without explicit operator review outside the tool.
- Makes the product easier to defend in a capstone design review: detection can be broad while automatic mutation remains intentionally narrow.
- Preserves the current TUI and CLI semantics, where host findings may explain what to change but do not claim `f` or `--fix` can safely do it for the operator.

## Consequences

- New remediation work should begin by asking whether the change still fits the Compose-only boundary; if not, it is a deliberate architecture expansion.
- Host findings must continue surfacing actionable guidance through `how_to_fix` and TUI context instead of through automatic writes.
- Fix UX work may improve previewing, filtering, and validation without changing the host-versus-Compose boundary.
- Any future host auto-remediation proposal requires a new ADR because it would change the product's safety model, not just add another fix rule.
