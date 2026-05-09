# ADR 0008: Distribution and Install Modes

**Date:** 2026-05-09
**Status:** Accepted

## Context

By the May 13 design review, hostveil ships through more than one delivery path:

- wrapper-managed install through `scripts/install.sh`
- direct release assets through tarballs
- package-managed installs through official `.deb` and `.rpm` assets

Those paths are not interchangeable. The wrapper install owns lifecycle commands such as `upgrade`, `uninstall`, and `auto-upgrade`, while package installs are intentionally owned by the system package manager.

The product also now publishes official packages for two CPU targets and uses a Rocky 9-compatible baseline for RPMs. That behavior is part of the architecture, not just a release script detail, because it defines how operators are expected to install and maintain the tool.

## Decision

hostveil supports two official install modes with intentionally different lifecycle semantics.

### 1. Wrapper-managed install

The `install.sh` path installs the wrapper-managed mode.

- lifecycle commands such as `hostveil upgrade`, `hostveil uninstall`, and `hostveil auto-upgrade enable|disable` are supported here
- launch-time auto-upgrade checks belong only to this mode
- this remains the primary quick-install path documented in the README

### 2. Package-managed install

The `.deb` and `.rpm` release assets install the package-managed mode.

- package installs do not self-update
- package installs do not support launch-time auto-upgrade
- lifecycle commands return package-manager guidance instead of trying to take ownership away from `apt`, `dnf`, or compatible tooling
- package-mode command behavior is still exposed through the same `hostveil` entrypoint, but lifecycle handling is intentionally different

Official release asset shapes are fixed to:

- tarballs
- `.deb`
- `.rpm`

Official release targets are fixed to:

- `x86_64`
- `aarch64`

RPM packages are built on a Rocky Linux 9 / RHEL 9 compatible baseline and are intended for Fedora-family and Rocky/RHEL 9-class systems.

## Why

- Avoids conflicting ownership between hostveil's wrapper lifecycle and the system package manager.
- Gives users a simple quick-install flow while still providing first-class distro package assets.
- Keeps package behavior honest: package installs should not pretend they can safely self-upgrade outside the package manager.
- Makes the release pipeline explainable during the design review because install mode, lifecycle semantics, and release packaging strategy are aligned.

## Consequences

- New distribution channels such as apt repository hosting, dnf repository hosting, Homebrew, or AUR are follow-up scope, not implied by the current package asset support.
- User-facing docs must keep install-mode semantics explicit whenever lifecycle commands are discussed.
- Release workflow changes that alter the official asset set, supported architectures, or RPM compatibility baseline are architecture-affecting changes and should be treated as such.
- Future install improvements should preserve the split between wrapper-owned lifecycle actions and package-manager-owned lifecycle actions unless a new ADR deliberately changes that boundary.
