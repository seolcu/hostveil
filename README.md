# hostveil v3.0.0

A single-binary Linux tool that scans a self-hoster's host for
common security misconfigurations across six categories (SSH,
Docker, image CVEs, reverse proxy, SSL/TLS, and system
hardening), presents the findings in plain language, and applies
reversible fixes with a built-in rollback path. v3 ships three
user surfaces — a CLI, an interactive TUI, and a local web
dashboard — plus an opt-in AI layer for richer explanations.

> v3 is a full rewrite from the previous v2.5.2 implementation.
> The v2.5.2 codebase is intentionally not present in this
> repository and is not referenced for any design or
> implementation decisions. The v3 binary is a single static
> Go executable.

## Install

Pick one of the following. All three produce a single static
binary at `/usr/local/bin/hostveil` (or wherever you choose).

### From a release tarball (v3.0.0+)

```bash
curl -L -o /tmp/hostveil.tgz \
  https://github.com/seolcu/hostveil/releases/download/v3.0.0/hostveil_3.0.0_linux_amd64.tar.gz
tar -xzf /tmp/hostveil.tgz -C /tmp
sudo install -m 0755 /tmp/hostveil /usr/local/bin/hostveil
hostveil version
```

### From source

```bash
git clone https://github.com/seolcu/hostveil
cd hostveil
make build
sudo install -m 0755 dist/hostveil /usr/local/bin/hostveil
hostveil version
```

## Surfaces

| Surface | Invocation | Status in v3.0.0 | Lands in |
|---|---|---|---|
| CLI | `hostveil scan` | full | v3.0.0 |
| CLI | `hostveil fix` | full | v3.0.0 |
| CLI | `hostveil rollback` | full | v3.0.0 |
| CLI | `hostveil explain` | full | v3.0.0 |
| CLI | `hostveil suppress` | full | v3.0.0 |
| TUI | `hostveil tui` | stub | v3.x |
| Web | `hostveil web` | stub | v3.x |
| AI | `hostveil ai ...` | stub | v3.x |

## Five-minute tour

```bash
# 1. Confirm the binary
hostveil version
# hostveil v3.0.0 (commit a1b2c3d, built 2026-06-18T...)

# 2. Run a scan
hostveil scan
# ... plain-language report on stdout ...

# 3. Apply a fix (with a preview + confirmation)
hostveil fix <finding-id>

# 4. Roll it back (byte-identical restore)
hostveil rollback <fix-record-id>

# 5. Ask "why"
hostveil explain <finding-id>
# ... plain-language what/why/how-to-verify ...

# 6. Silence a noisy rule
hostveil suppress hardening_sysctl.baseline --reason "intentional on this host"
```

## Surfaces detail

### `hostveil scan`

```
hostveil scan [--categories=<csv>] [--refresh-cve] [--report-dir=<dir>] [--no-report-file]
```

- Default behavior: full scan, output to stdout and to
  `~/.local/share/hostveil/reports/`.
- `--no-report-file` writes to stdout only.
- Exit code: 0 (no high/critical), 1 (at least one), 2 (errored).

### `hostveil fix <finding-id-or-fingerprint>`

```
hostveil fix <id> [--yes] [--force] [--no-restart]
```

- Renders a preview of the change, prompts for confirmation,
  backs up the affected file, records a FixRecord, and applies
  the change.
- `--force` overrides the FR-011 conflict detector (e.g. an SSH
  Match block that re-enables the setting being disabled).
- Without `--yes`, prompts at the terminal.

### `hostveil rollback <fix-record-id>`

```
hostveil rollback <id> [--yes]
```

- Restores the affected file from the backup and writes a
  follow-up FixRecord whose `rolled_back_via` points at the
  original.
- Byte-identical (SC-003) verified by `internal/fix.VerifyByteIdentical`.

### `hostveil explain <finding-id-or-rule-id>`

```
hostveil explain <id> [--ai]
```

- Looks up the finding first; falls back to a built-in
  rule_id catalog with plain-language explanations.
- `--ai` is reserved for the v3.x AI layer; v3.0.0 falls back
  to the built-in explanation.

### `hostveil suppress <rule-id> [--reason=<text>] [--list]`

- Per-host rule suppression; the orchestrator re-labels any
  matching finding as `state=suppressed` on the next scan.
- `--list` shows the current suppressions for the host.

## Build variants

```bash
make build              # default binary
make build-noai         # excludes all AI code (CI-verified)
make build-notui        # excludes the TUI subcommand
make build-noweb        # excludes the Web UI subcommand
make build-cross        # cross-compile to linux/{amd64,arm64,386,arm/v7}
```

The `noai` build is verified to contain no `(?i)anthropic|openai|ollama`
literals (CI gate).

## Architecture (one-pager)

```
              +---------------------------+
              |       cmd/hostveil        |
              |  (main: cobra dispatcher)  |
              +-------------+-------------+
                            |
              +-------------v-------------+
              |       internal/cli         |  (scan, fix, rollback, explain, suppress, ...)
              +-------------+-------------+
                            |
              +-------------v-------------+
              |       internal/scan        |  (orchestrator, fingerprint, classification)
              +-------------+-------------+
                            |
              +-------------v-------------+
              |     internal/checks/      |  (ssh, docker, images, proxy, ssl, hardening)
              +-------------+-------------+
                            |
              +-------------v-------------+
              |     internal/fix          |  (preview, backup, apply, rollback, conflict)
              +-------------+-------------+
                            |
              +-------------v-------------+
              |    internal/store         |  (SQLite, migrations, typed accessors)
              +-------------+-------------+
                            |
              +-------------v-------------+
              |   ~/.local/share/hostveil |
              |   - state.db (SQLite)     |
              |   - reports/              |
              |   - backups/              |
              |   - logs/                 |
              +---------------------------+
```

For the full architecture, threat model, build-time tag matrix,
and privacy posture, see [docs/how-it-works.md](docs/how-it-works.md).

## Documentation

- [docs/how-it-works.md](docs/how-it-works.md) — architecture,
  threat model, build tags, privacy
- [docs/contributing.md](docs/contributing.md) — dev setup, TDD
  discipline, build/test, release process
- [specs/001-selfhost-security/plan.md](specs/001-selfhost-security/plan.md) —
  the implementation plan
- [specs/001-selfhost-security/spec.md](specs/001-selfhost-security/spec.md) —
  the user stories and functional requirements
- [specs/001-selfhost-security/quickstart.md](specs/001-selfhost-security/quickstart.md) —
  the canonical five-minute tour
- [CHANGELOG.md](CHANGELOG.md) — what changed in v3.0.0

## License

GPL v3, inherited from the v2.5.2 codebase. See [LICENSE](LICENSE).
