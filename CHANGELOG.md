# Changelog

All notable changes to hostveil are recorded in this file.
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- **Web UI XSS in detail panel.** `body.dataset.full` and
  `body.dataset.truncated` are now re-escaped before being
  injected as HTML on the "View more" / "View less" toggle.
  The browser auto-decodes HTML entities in `data-*` attributes
  back to raw characters, so the previous direct interpolation
  turned descriptions containing `<script>` (or any HTML) into
  live markup. Finding description / how_to_fix text originates
  from local scan sources (Trivy, Lynis, compose YAML), so a
  description with attacker-controlled content rendered as
  working script.

## [2.5.2]  2025-xx-xx

### Changed
- TUI and Web UI share the same in-memory snapshot via `domain.Snapshot`.
- Score is a 4-axis weighted model with per-axis penalty caps.

## [2.5.0]

### Fixed
- SSH-7408 expanded to 5 independent actions (one per sshd directive)
  instead of a single bundled fix that forced all-or-nothing.
- KRNL-6000 reverted to 6 separate sysctl actions for the same reason.

## [2.0.0]

### Added
- Initial open-source release.
- Three scanner backends: Trivy (CVE + IaC), Lynis (host hardening),
  and a native Docker Compose audit.
- Embedded Web UI served from the same binary (no Node, no build chain).
- Axis-based scoring (Vulnerabilities, Container exposure, Host
  hardening, Secrets) with per-axis penalty caps.
- Four remediation kinds: Auto, Review, Manual, Unavailable.
- Pre-change checkpoints with rollback via `hostveil rollback <id>`.
- Cross-platform installer (`scripts/install.sh`) tested against
  Ubuntu, Debian, Fedora, Arch, Alpine, and openSUSE.

[Unreleased]: https://github.com/seolcu/hostveil/compare/v2.5.2...HEAD
[2.5.2]: https://github.com/seolcu/hostveil/compare/v2.5.0...v2.5.2
[2.5.0]: https://github.com/seolcu/hostveil/compare/v2.0.0...v2.5.0
[2.0.0]: https://github.com/seolcu/hostveil/releases/tag/v2.0.0
