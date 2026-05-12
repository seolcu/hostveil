# ADR 0006: Core Scan Result and Adapter Contract

**Date:** 2026-05-09
**Status:** Accepted

## Context

hostveil combines findings from native Compose analysis, native host checks, and optional external adapters inside one TUI-first product.

That creates a maintenance risk: if each scanner keeps its own result shape, every output path would need scanner-specific branching and the architecture would expand every time a new adapter is added.

The current product already depends on one shared findings pipeline for:

- TUI overview and findings views
- JSON export
- score calculation
- scan history recording
- future report surfaces that reuse the Rust result model

The contract should stay fixed so later adapter work extends the existing model instead of redefining it.

## Decision

Use `ScanResult` as the single product-level scan contract.

`ScanResult` contains three top-level concerns:

- `findings`: the unified issue list
- `score_report`: the coverage-aware score summary
- `metadata`: scan context, warnings, discovered services/projects, and adapter status

`Finding` is the normalized issue unit shared by native checks and adapters. Each finding must carry:

- `id`
- `axis`
- `severity`
- `scope`
- `source`
- `subject`
- `related_service`
- `title`
- `description`
- `why_risky`
- `how_to_fix`
- `evidence`
- `remediation`

The shared taxonomy is fixed around the existing Rust domain model:

- `Axis`: Sensitive Data, Excessive Permissions, Unnecessary Exposure, Update / Supply Chain Risk, Host Hardening
- `Scope`: Service, Image, Host, Project
- `Source`: Native Compose, Native Host, Trivy, Lynis, Dockle
- `RemediationKind`: Manual, Auto, Review

Optional adapters are treated as coverage extenders, not as separate result systems.

- Adapter findings must map into the same `Finding` structure used by native checks.
- Adapter findings must project onto the existing `axis`, `scope`, `source`, and `remediation` taxonomy.
- Adapter readiness/failure is represented in `ScanMetadata.adapters` through `AdapterStatus`, not through parallel result payloads.

host findings, Compose findings, and image findings stay in one shared findings pipeline and are differentiated by `scope`, `source`, and `subject`, not by separate top-level result objects.

## Why

- Keeps the TUI, JSON export, scoring, and history paths aligned on one contract.
- Lets new adapters extend coverage without forcing UI, export, or scoring redesign.
- Makes host and Compose findings comparable inside one action queue and findings view.
- Preserves the existing Rust implementation shape instead of introducing scanner-specific forks.

## Consequences

- New adapters must normalize into the shared domain model before they reach product surfaces.
- Changes to `ScanResult`, `Finding`, or the shared taxonomy are architectural changes and should be treated as ADR-level decisions.
- The score report remains coverage-aware because all findings, regardless of source, feed one scoring pipeline.
