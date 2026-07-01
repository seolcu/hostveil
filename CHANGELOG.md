# Changelog

All notable changes to hostveil are recorded in this file.
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **`compose.ds016`: Docker socket mount detection.** Flags any service
  that bind-mounts `/var/run/docker.sock` or `/run/docker.sock` —
  equivalent to root on the host, even mounted `:ro`. Registered as an
  Auto fix (remove the mount) with a warning to use a socket proxy
  (e.g. `tecnativa/docker-socket-proxy`) if the service genuinely needs
  Docker API access.
- **`compose.ds017`: sensitive host directory mounted read-write.**
  Flags read-write bind mounts of `/`, `/etc`, `/root`, `/home`,
  `/boot`, `/proc`, `/sys`, `/run`, `/var/run`, or any `.ssh` directory.
  Registered as a Review fix (add `:ro`, or remove the mount).
- **`compose.ds018`: unauthenticated-by-default datastore exposed.**
  Flags a service running Redis, Mongo, Memcached, Elasticsearch,
  CouchDB, or etcd that publishes a port on `0.0.0.0`. These images
  ship with authentication off by default (Redis "protected mode",
  Mongo with no `MONGO_INITDB_ROOT_*`) or are commonly deployed
  without it. Critical severity — an exposed Redis can be used to
  write an SSH `authorized_keys` file for remote code execution.
  Registered as an Auto fix (remove the port mapping — other compose
  services still reach it over the Docker network) with a warning.
- **`compose.ds019`: admin panel exposed on all interfaces.** Flags
  Portainer, phpMyAdmin, Adminer, or mongo-express published on
  `0.0.0.0` — the top compromise vector for self-hosted setups per
  community post-mortems (mass scanners like Shodan index exposed
  admin panels within hours). Registered as a Review fix (bind to
  `127.0.0.1`, or remove the mapping).
- **AI remediation brief export.** Both UIs can now export a local
  Markdown brief for ChatGPT, Claude, or a local LLM. The brief includes
  a prompt-injection warning, active findings prioritized by severity,
  score/count summaries, existing hostveil guidance, and redacted
  evidence/metadata so users can ask for a remediation plan without
  uploading the raw JSON report.
- `hostveil history` and `hostveil rollback` are now documented in the
  main README (they existed already but weren't listed), along with
  `hostveil tui-web` and the `--cert-file`/`--key-file` TLS flags.
- **Rewrote `README.md`.** The old opening line described hostveil as
  a scanner and buried the actual differentiator — that it fixes
  findings, not just reports them — 30 lines down inside an FAQ
  answer. The comparison against running Trivy/Lynis separately (the
  first question anyone evaluating hostveil asks) is now the second
  thing in the file. Added CI/license/release/Go-version badges,
  moved reference tables (score axes, TUI key list, Web UI API) into
  collapsed `<details>` so the main read stays short, and replaced
  the ASCII data-flow diagram with a Mermaid flowchart. Corrected
  claims that didn't match the code: hostveil also talks to GitHub
  from `hostveil setup` (not just the update check), and a shell-type
  fix (a package install, a `sysctl -w`) has no file to back up and
  cannot be rolled back the same way a file-edit fix can.
- **Restructured `hostveil --help`.** Was a single flat 17-line list
  mixing primary commands with E2E-testing flags in installation
  order. Now opens with a one-line description and groups commands
  by intent (Run / Configure / Maintain / History), matching the
  README's structure.
- **The TUI and Web UI headers still said "Linux self-hosting
  security scanner"** — the exact old positioning the README rewrite
  replaced, but hardcoded as a persistent on-screen header in both
  UIs, which is more load-bearing than the README since it's what
  every user sees on every run. Both now read "Finds and fixes
  security issues", matching the README's opening line.
- **Documented the `RemediationKind` zero-value footgun.**
  `RemediationAuto` is `0`, so a `domain.Finding` built without
  explicitly setting `Remediation` silently reads as "Auto-fixable"
  (and `IsFixable()` returns `true` for it) even though no fix was
  ever registered for it. Every scanner already sets this field
  explicitly (verified via `ast_grep` across all four
  Finding-construction sites), so this was never reachable in
  practice — but it's a real trap for a future custom rule or fix
  author. Added doc comments on `RemediationKind` and `Finding`, plus
  `TestRegistry_Classify_UnregisteredIDLeavesRemediationUnchanged` to
  make the invariant explicit: `Registry.Classify` only overwrites
  `Remediation` for a finding ID it recognizes — an unrecognized ID's
  `Remediation` is whatever the caller already set it to, which is
  exactly why every constructor must set it.
- **`internal/trivy/README.md` described a dead architecture.**
  Claimed hostveil shells out to `trivy config` for compose
  misconfigurations (via a `scanConfig` function that no longer
  exists), when that scan was actually removed a month ago in favor
  of the native `internal/composeaudit` package specifically
  because it never produced compose findings in practice. The
  package doc comment (`trivy.go` line 1) already said "image
  scans" correctly; only the README had drifted. Also corrected the
  same stale "CVE + IaC" claim in three places in `AGENTS.md`
  (the architecture table, the important-files table's function
  list for `trivy.go`, and the runtime-deps list), the
  `compose.ds*`/`compose.dr*` rule-ID scheme (`AGENTS.md` still said
  `DR-001 … DR-019`, an uppercase scheme this codebase never used
  post-rewrite), the README's Mermaid diagram (labeled Trivy
  "image + config scan"), and the README's "Can I add my own rule?"
  answer (named only two of the three fix files, omitting
  `internal/fix/images.go`). Also updated `AGENTS.md`'s LoC count,
  stale since well before this session (~13.5k when the codebase is
  actually ~17k including tests, ~8.4k without).

### Fixed
- **`compose.dr002` never detected long-syntax port exposure.**
  `checkPortBinding` compared the ports node's YAML `Kind` against the
  wrong numeric constant, so the entire long-syntax branch (`target:` /
  `published:` / `host_ip:` mapping form) was dead code. A separate
  early-return on empty short-syntax ports also skipped the long-syntax
  check entirely for any service using only long-syntax mappings.
- **`compose.dr003` fix over-applied `:ro`.** The finding didn't record
  which volume triggered it, so applying the fix appended `:ro` to
  every non-`:ro` volume on the service instead of just the flagged one.
- **TUI applied a fix without cascading to related findings.** The Web
  UI's `/api/fix` marks other findings resolved by the same exact-ID
  fix on the same service (`MarkRelatedFixed`), but the TUI's fix
  handler only marked the single finding, leaving related findings
  showing as unfixed until the next rescan. Both UIs now cascade
  identically.
- **Trivy findings with a GHSA-only ID (no CVE assigned) were
  permanently stuck as `Unavailable` and scored under the wrong axis.**
  Trivy reports some vulnerabilities (common in npm/pip/gem ecosystem
  advisories from GitHub Security Advisories) under a bare
  `GHSA-xxxx-xxxx-xxxx` `VulnerabilityID` with no CVE ever assigned.
  The fix registry's wildcard (`trivy.cve-*`), the CVE-vs-Manual
  override, and the scoring axis router all matched only the
  `trivy.cve-` prefix, so these findings never got classified (stuck
  at `Unavailable`, contradicting the invariant that `Unavailable` is
  never user-visible after a complete scan) and scored under
  "Container exposure" instead of "Vulnerabilities" (wrong penalty
  cap: 30 vs 35). All three now match on `trivy.*`.
- **TUI mutated the live snapshot's `Findings` slice directly, racing
  with concurrent readers.** `fixResultMsg`'s handler wrote
  `m.snap.Findings[i].Fixed = true` on a snapshot returned by
  `ScanProgress.Snapshot()`. Because `Snapshot()` caches and returns a
  shallow copy that can alias the same backing array across multiple
  calls, this unsynchronized write could race with any concurrent
  `Snapshot()` caller — e.g. the Web UI's HTTP handlers in `hostveil
  tui-web`, which runs the TUI and Web server against one shared
  `ScanProgress`. Now goes through the mutex-protected `MarkFixed`.

### Security
- **`GET /api/result` was vulnerable to DNS rebinding.** Unlike the
  POST endpoints, it had no `Origin` check at all — a page on any
  domain that later got DNS-rebound to `127.0.0.1` could `fetch()` it
  and exfiltrate the full scan snapshot (findings, evidence, hostname,
  local IP). More fundamentally, the existing `sameOrigin(Origin,
  Host)` CSRF check used on the POST endpoints does not defend against
  this class of attack anyway: after a successful rebind, both
  `Origin` and `Host` read as the attacker's domain, so they match
  each other by construction and the check passes. Added `hostGuard`,
  applied globally to every route, which validates `Host` against a
  fixed allowlist derived from how the server was actually bound
  (independent of anything the client sends) rather than against
  another client-controlled header.
- **Scan history and fix checkpoints were world-readable.**
  `/var/lib/hostveil/{checkpoints,scans}` and their contents were
  created `0755`/`0644`. Checkpoint diffs and full scan snapshots can
  contain secrets (a compose file's hardcoded password sitting in the
  context lines of an unrelated diff, or the evidence attached to a
  `compose.dr004` finding), so any local user could read them
  regardless of the audited file's own permissions. Both are now
  owner-only (`0700`/`0600`), and `EnsureDirs` now `chmod`s existing
  directories left behind by older hostveil versions.
- **The TUI applied fixes without a checkpoint.** Only the Web UI's
  `/api/fix` created a checkpoint, so `hostveil rollback` could not
  undo a fix applied from the TUI (the default entry point). Both UIs
  now go through the shared `history.ApplyWithCheckpoint`.
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
- **`hostveil update` installed the downloaded release archive with
  zero checksum verification**, despite `SECURITY.md` documenting that
  it "re-verifies checksums before installing." Now fetches and
  verifies the release's `hostveil-checksums.txt` before installing,
  and fails closed (aborts, does not install) if the checksum is
  missing or does not match.
- **`scripts/install.sh.sha256` did not exist**, so `hostveil setup`'s
  installer-checksum verification silently no-op'd on every run (the
  checksum fetch 404'd, which the fail-open check treats as "skip").
  Published the checksum file and added a CI check
  (`sha256sum -c scripts/install.sh.sha256`) so it can never silently
  drift again.

## [2.5.2] — 2025-xx-xx

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
