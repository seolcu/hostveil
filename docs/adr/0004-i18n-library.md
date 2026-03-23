# ADR 0004: Rust i18n Library

**Date:** 2026-03-23
**Status:** Accepted

## Context

hostveil already requires that every user-visible string go through localization. The Rust product is still early, so the i18n choice should be lightweight, easy to wire into a terminal binary, and simple enough to use from the first bootstrap screens onward.

The main candidates considered were:

- `rust-i18n`
- `fluent-rs`

## Decision

Use **`rust-i18n`** for Rust v1.

## Why

- It is lightweight and easy to bootstrap in a binary crate.
- The macro-based API is simple enough that strings can flow through the i18n layer immediately instead of being postponed until later.
- The locale file format is straightforward for the current project scale.
- It is a better fit for a terminal-first tool with mostly concise UI copy than the added expressive power of Fluent.

## Why not `fluent-rs`

- Fluent is powerful, but its flexibility adds conceptual and implementation weight that the project does not need yet.
- The early Rust milestones benefit more from low friction than from a more advanced message system.

## Consequences

- The crate should define locale files from the start and keep new strings out of hardcoded English paths.
- If the product later needs more advanced grammatical or localization behavior, the team can revisit the decision in a future ADR.
