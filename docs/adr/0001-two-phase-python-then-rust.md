# ADR 0001: Two-Phase Implementation — Python Prototype then Rust TUI

**Date:** 2026-03-15
**Status:** Accepted

## Context

hostveil needs to solve two competing problems:

1. **Rapid iteration** — the rule engine (security checks, scoring model, Quick Fix logic) is complex and uncertain. The right rules and edge cases need to be discovered through experimentation, not designed upfront.
2. **Lightweight deployment** — the final product must run on minimal self-hosted servers without requiring a Python runtime, heavy dependencies, or significant memory overhead.

## Decision

Implement in two sequential phases:

1. **Python CLI prototype** (`proto/`, weeks 3–8): Implement all core logic in Python. Validate the rule engine, scoring model, and Quick Fix behaviour against real Docker Compose configurations. Python allows fast iteration and easy refactoring during the discovery phase.

2. **Rust TUI** (`src/`, weeks 8–14): Port the validated logic to Rust. Add the terminal dashboard UI using `ratatui` (or equivalent — see ADR 0002). The Rust binary is self-contained, fast, and suitable for distribution via `cargo install` or a shell installer script.

## Consequences

- Rule logic is written twice. This is acceptable: the Python phase is a design tool, not a deliverable. The cost of rewriting in Rust is outweighed by avoiding premature commitment to a design that may change.
- The Python prototype must **not** be packaged or distributed as a product.
- Architectural decisions made during the Python phase (rule schema, scoring weights, Quick Fix tiers) become the contract for the Rust implementation. Document them as ADRs when they stabilise.
- `proto/` and `src/` must remain strictly separated — no shared code, no symlinks, no cross-references.
