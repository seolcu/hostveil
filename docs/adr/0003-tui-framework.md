# ADR 0003: Rust TUI Framework

**Date:** 2026-03-23
**Status:** Accepted

## Context

The real product is TUI-first, Linux-focused, and needs enough layout control to present a dashboard, finding lists, detail panes, review flows, and eventually fix previews. The UI should stay lightweight and fit a single self-contained binary.

The main candidates considered were:

- `ratatui` with `crossterm`
- `cursive`

## Decision

Use **`ratatui` with `crossterm`**.

## Why

- `ratatui` is the strongest fit for a dashboard-style layout with custom panes, severity-driven lists, help bars, and diff review widgets.
- `crossterm` is a practical cross-platform terminal backend and still works well even though the runtime target is Linux-first.
- The pair has active community usage, examples, and ecosystem momentum.
- The architecture keeps rendering and app state explicit, which fits a security tool whose UI will evolve around findings, filters, and remediation flows.

## Why not `cursive`

- `cursive` is attractive for forms and higher-level widgets, but hostveil needs more layout control than a form-centric app.
- The project is likely to need custom panels and richer finding visualization rather than mostly predefined dialog widgets.

## Consequences

- The Rust crate should depend on `ratatui` and `crossterm` from the start.
- The TUI code should be structured around explicit app state and render functions rather than tightly coupling business logic to widget callbacks.
- Non-interactive JSON export remains separate from the TUI and should not depend on terminal rendering concerns.
