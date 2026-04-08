# ADR 0005: Scoring Model for Rust v1

**Date:** 2026-04-08
**Status:** Accepted

## Context

hostveil needs a single score that is easy to understand for self-hosting operators, while still showing where risk clusters by axis.

The Python prototype validated a simple Compose-focused scoring model:

- Each finding contributes a fixed severity penalty to its axis.
- Per-axis score is `100 - sum(penalties)`, clamped to `[0, 100]`.
- Overall score is a weighted sum of per-axis scores.

Rust v1 expands the scope to include a fifth target axis (Host Hardening) and optional adapter findings (e.g., Trivy) without breaking parity with the validated Compose behavior.

## Decision

Use a penalty-based axis scoring model with a coverage-aware weighted overall score.

### Severity penalties

Severity penalties are fixed and match the Python prototype:

| Severity | Penalty |
|---|---:|
| Critical | 75 |
| High | 35 |
| Medium | 15 |
| Low | 5 |

### Axes

Rust v1 represents five axes:

1. Sensitive Data
2. Excessive Permissions
3. Unnecessary Exposure
4. Update / Supply Chain Risk
5. Host Hardening

### Coverage-aware weights

Overall score weights depend on which domains are covered by the scan:

- **Compose-only scans** (default in v1):
  - Sensitive Data: 0.35
  - Excessive Permissions: 0.30
  - Unnecessary Exposure: 0.20
  - Update / Supply Chain Risk: 0.15
  - Host Hardening: 0.00

- **Compose + Host Hardening scans**:
  - Sensitive Data: 0.30
  - Excessive Permissions: 0.25
  - Unnecessary Exposure: 0.15
  - Update / Supply Chain Risk: 0.15
  - Host Hardening: 0.15

- **Host-only scans**:
  - Host Hardening: 1.00 (all other axes: 0.00)

An axis with weight `0.0` does not affect the overall score, even if findings exist for that axis.

## Why

- Keeps parity with the validated Python Compose scoring for v1 Compose-only scans.
- Produces an intuitive score: severe permission / host failures pull the score down much more than low-risk hygiene findings.
- Allows optional adapter findings to influence the score via their axis without introducing a second scoring system.
- Coverage-based weighting avoids penalizing a scan for axes that were not actually assessed.

## Consequences

- Weight decisions are treated as user-facing product behavior and must be backed by tests.
- New axes or scan domains require updating both the weights and the tests that assert expected ordering (low-risk vs high-risk outcomes).
- Optional adapters should map findings onto one of the existing axes so they naturally integrate into the same score report.
