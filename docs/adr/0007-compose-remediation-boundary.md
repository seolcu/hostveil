# ADR 0007: Remediation Boundary (Expanded for Adapter Findings)

**Date:** 2026-05-09 (initial), 2026-05-12 (expanded)
**Status:** Accepted (updated)

## Context

hostveil is a security dashboard for self-hosted operators, but its remediation features write configuration back to real systems.

That creates a safety problem: automatic fixes are valuable only when they stay reviewable, reversible, and narrowly scoped. The initial v1 release limited writes to Docker Compose files and treated host findings as manual triage items.

As usage grew, operators running external scanners (Dockle, Lynis) asked for remediation paths that matched those scanners' recommendations. Rather than requiring operators to context-switch between tools, the fix engine was expanded to handle scanner-specific fix actions through a structured action taxonomy.

## Decision

The fix engine supports three action types, each with distinct safety properties:

- **`ComposeEdit`** — edits to a Docker Compose YAML file (same safety model as v1: preview → backup → atomic write).
- **`HostEdit`** — edits to a host configuration file (e.g., `/etc/ssh/sshd_config`, `/etc/sysctl.d/99-hardening.conf`). Operator review required via `Review` remediation kind.
- **`ShellCommand`** — execution of a shell command (e.g., `chmod`, `ufw`, `lynis audit`). Non-interactive; output is logged.

The three kinds map to remediation workflows:

- `Auto`: changes hostveil can complete end-to-end after the diff review
- `Review`: changes hostveil can drive, but only after the operator confirms

Implementation boundaries:

- Adapter findings (Dockle, Lynis) reach the fix engine through the `external_findings` pipeline, separate from native Compose rule findings.
- `preview_with_external` / `apply_with_external` accept adapter findings alongside native findings.
- `ComposeEdit` actions from adapters are merged into the Compose document alongside native edits.
- `HostEdit` actions create backup copies of target files before writing.
- `ShellCommand` actions execute via `sh -c` and report exit status.
- Preview comes before apply for all action types.
- Compose file writes create a timestamped backup. Host file edits also create backups.

### Adapter-to-Action Mapping

| Source | Finding Evidence | FixAction | Remediation |
|--------|-----------------|-----------|-------------|
| Dockle DKL-DI-0006 | `sample_codes` | ComposeEdit (HEALTHCHECK) | Auto |
| Dockle DKL-DI-0003 | `sample_codes` | ComposeEdit (no-new-privileges) | Auto |
| Dockle DKL-DI-0005 | `sample_codes` | ComposeEdit (user directive) | Review |
| Dockle DKL-DI-0001 | `sample_codes` | ComposeEdit (cap_drop) | Review |
| Lynis SSH-7408/7411 | `sample_test_ids` | HostEdit (sshd_config) | Review |
| Lynis KRNL-5820 | `sample_test_ids` | HostEdit (sysctl) | Review |
| Lynis FILE-7524/7530 | `sample_test_ids` | ShellCommand (permissions) | Auto |
| Lynis (fallback) | any | ShellCommand (lynis audit) | Review |

## Why

- Allows operators to remediate scanner findings without leaving hostveil.
- Keeps write safety through preview, backup, and review gates.
- Avoids mutating live host posture without explicit operator review for high-risk changes (`HostEdit` is always `Review`).
- Maintains the existing TUI and CLI semantics where `f` and `--fix` trigger the same pipeline.
- Preserves the original Compose-only safety model for changes that do not involve external adapters.

## Consequences

- New adapter integrations (e.g., Trivy, Gitleaks) should add `classify_*` functions in `src/src/fix/adapter.rs`.
- Host findings with explicit scanner test IDs can now produce `HostEdit` or `ShellCommand` actions.
- The `FixPlan` struct carries `compose_actions`, `host_actions`, and `system_actions` as separate vectors.
- The fix review TUI (`fix_review.rs`) displays all three action types with color-coded labels.
- Any future expansion to new action types (e.g., `DockerfileEdit`, `KubernetesPatch`) requires a new ADR.
