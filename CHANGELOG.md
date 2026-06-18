# Changelog

All notable changes to hostveil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-06-18

### Added

- **Full rewrite from scratch.** v3 is a fresh codebase; the
  v2.5.2 implementation is intentionally not present in this
  repository and is not referenced for any design or implementation
  decision. The v3 binary is a single static Go executable
  (`go build -trimpath`, no CGO) that runs on `linux/amd64` and
  `linux/arm64`.

- **Six scan categories** (`hostveil scan`):
  - `ssh` — PermitRootLogin, PasswordAuthentication, Protocol
    rules (FR-001).
  - `docker` — runs-as-root, privileged, exposed-public-port,
    compose-`:latest`-tag (FR-002).
  - `image_cve` — placeholder for the post-v3.0 CVE cache fill
    (FR-003).
  - `reverse_proxy` — nginx http{} and Caddyfile parsers;
    server-tokens, security-headers, exposed-path,
    no-rate-limit (FR-014).
  - `ssl_tls` — PEM walker for `/etc/ssl/certs` and
    `/etc/pki/tls/certs`; expired / expiring-soon findings
    (FR-015).
  - `hardening` — five sub-checks (firewall, fail2ban,
    unattended-upgrades, sysctl baseline of 13 keys, pending
    security updates) (FR-016, FR-017).

- **`hostveil fix <finding-id>`** — preview, confirmation,
  backup, record, and apply (FR-005..FR-007). The backup is
  byte-for-byte verified and rollback restores exactly
  (SC-003).

- **`hostveil rollback <fix-record-id>`** — restores the affected
  file from the backup and writes a follow-up FixRecord
  whose `rolled_back_via` points at the original record.

- **`hostveil explain <finding-id-or-rule-id>`** — plain-language
  explanation of a finding or a built-in rule catalog.

- **`hostveil suppress <rule-id>`** and `--list` — per-host rule
  suppression; the orchestrator re-labels matching findings as
  `[suppressed]` on the next scan.

- **Conflict detection (FR-011)** — the apply flow refuses to
  proceed without `--force` when the SSH Match block, the
  `/etc/ssh/sshd_config.d/` drop-ins, or the Compose override
  file would re-assert the pre-fix value.

- **SQLite state store** at `~/.local/share/hostveil/state.db` with
  WAL, foreign keys, busy timeout. Forward-only migrations; the
  initial migration creates all 17 tables from
  `contracts/state-db.md`. A second migration relaxes the strict
  FKs on `findings.fix_id` and `fix_records.fix_id` so the
  v3.0.0 binary can write FixRecords before the fixes catalog
  is seeded (the catalog lands in v3.x and the FKs come back).

- **Reproducible build** via `scripts/build.sh` with `-trimpath`
  and recorded `BUILDINFO` (version, commit, build date). The
  build hashes the produced binary so a CI rerun can verify
  reproducibility.

- **Build-time AI exclusion** via the `noai` Go build tag. A
  binary built with `-tags noai` is verified to contain no
  `(?i)anthropic|openai|ollama` literals (CI gate).

- **Structured logging** via `log/slog` JSON handler with
  `component` and `scan_run_id` correlation.

- **Re-redaction** of the persisted report file: PEM private
  keys, named credential fields, URL credentials, and AWS access
  keys are stripped before write (FR-020).

- **Exit code contract (0/1/2)** — 0 when no high/critical, 1
  when at least one, 2 on scan error. The scan subcommand
  translates the `HitError` sentinel into exit code 1.

- **9 subcommands** — `scan`, `fix`, `rollback`, `explain`,
  `suppress`, `version`, `tui` (stub), `web` (stub), `ai
  <method>` (stub).

### Changed

- The license remains **GPL v3**, preserved from the v2.5.2
  codebase. v3 inherits this license; the previous commit
  (T008) that introduced a stray MIT license was reverted.

### Notes

- The TUI (`hostveil tui`), Web dashboard (`hostveil web`),
  and AI layer (`hostveil ai ...`) are stubbed at the CLI
  surface; the real implementations land in v3.x.
- The fixes catalog is empty in v3.0.0; the apply flow uses
  a placeholder procedure and records it as
  `procedure_used = "v3.0.0-alpha-placeholder"`. The v3.x
  release replaces this with a real per-rule catalog.
- The CVE feed adapter is not implemented; the `image_cve`
  category no-ops with an empty finding list. Post-v3.0.
