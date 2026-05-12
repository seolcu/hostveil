# ADR 0002: Rust V1 Scope and Support Policy

**Date:** 2026-03-23
**Status:** Accepted

## Context

The Python prototype proved the core Compose parser, rule engine, scoring model, and safe remediation flows. It also clarified that the real product should not stop at Docker Compose misconfiguration checks.

hostveil is meant to help self-hosters understand the security posture of an actual Linux server running self-hosted services. That includes Compose configuration, host hardening, image risk, and signals from existing tools such as Trivy or Lynis.

At the same time, the project still needs a clear v1 boundary. Trying to replace every security tool directly would create an unbounded scope and delay the real product.

## Decision

1. **Rust is now the active product implementation.**
   - `proto/` remains a frozen reference implementation for validated Compose behavior.
   - New product work defaults to `src/` unless a task explicitly says otherwise.

2. **V1 runtime support is Linux only.**
   - hostveil targets Linux self-hosted servers.
   - Windows contributors are supported through WSL, not through native Windows runtime support.

3. **V1 is TUI-first, with minimal headless JSON export.**
   - The main user experience is the interactive Rust TUI.
   - A non-interactive JSON output path exists for automation, regression tests, and report generation.

4. **The Rust product is integration-first.**
   - hostveil combines native checks with optional external scanner results.
   - External tools remain optional at runtime; missing tools reduce coverage rather than breaking scans.

5. **The target audit model expands to five axes.**
   - Sensitive Data Exposure
   - Excessive Permissions
   - Unnecessary Exposure
   - Update / Supply Chain Risk
   - Host Hardening

6. **Native remediation stays intentionally safety-first in v1.**
   - Compose remediation remains the default path for automatic fixes.
   - Adapter-driven host-level actions are allowed when they fit the fix engine contract: previewable where applicable, backup-safe where files are written, explicit in review UI, and bounded to well-understood actions such as `HostEdit` and `ShellCommand`.
   - hostveil still does not try to replace every host hardening task with automation; unsupported or high-risk changes remain guidance-only.

## Consequences

- The Rust implementation should use a generalized findings model rather than a Compose-service-only model.
- TUI and JSON export should consume the same scan result structure.
- Optional adapters such as Trivy, Dockle, Lynis, and Gitleaks can be added without making them installation blockers.
- Any new remediation-capable adapter must document its action boundary through the ADR set and the fix engine contract.
- CI and release workflows should focus on Linux artifacts first.
- Documentation should steer Windows contributors toward WSL and should not promise native Windows runtime support.
