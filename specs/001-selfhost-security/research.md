# Research: Hostveil v3.0.0

**Phase**: 0 (Outline & Research)
**Date**: 2026-06-18
**Spec**: [spec.md](./spec.md)
**Plan**: [plan.md](./plan.md)

This document resolves the "NEEDS CLARIFICATION" and "deferred" items
from the spec and the plan's Technical Context. Each entry follows the
shape **Decision / Rationale / Alternatives considered** so the planning
team can audit each choice and revisit it if a constraint changes.

---

## R-001. Language and runtime

**Decision**: Go 1.22+, single static binary, default build without
CGO.

**Rationale**:
- Single static binary matches spec FR-009 ("MUST NOT require the user
  to install or learn any extra framework, runtime, or service to run
  a scan").
- Pure-Go SQLite (`modernc.org/sqlite`) keeps the default build
  CGO-free, which fits the Constitution's "deterministic builds"
  constraint (no glibc version coupling, no C toolchain dependency on
  the build host).
- Strong test-first story (Principle III) and a mature standard
  library for system inspection (`os/exec`, `crypto/tls`,
  `crypto/x509`, `log/slog`).
- Cross-compilation trivially covers `linux/amd64` and `linux/arm64`
  with the same source tree.

**Alternatives considered**:
- **Rust**: same single-binary outcome, but a much slower write
  velocity for a v3 rewrite of this size, and a smaller pool of
  existing security-tooling crates we could lean on. Rejected for v3;
  kept as a future port target if a perf-critical path needs it.
- **Python**: violates FR-009 (runtime required on the target host)
  and complicates the reproducible-build story. Rejected.
- **Bash + POSIX tools**: cannot satisfy the Library-First principle
  in any meaningful sense, and is untestable as a unit. Rejected.

---

## R-002. Storage layer

**Decision**: SQLite via `modernc.org/sqlite` (pure Go), one database
file at `~/.local/share/hostveil/state.db`.

**Rationale**:
- Single-host, single-user product; SQLite's concurrency model is
  sufficient (serialized writer, multiple readers via WAL).
- The scan-history and finding-fingerprint logic (FR-008) needs
  indexed lookups by (host, category, fingerprint) — trivial in
  SQL, painful as flat files.
- Pure-Go driver means the default build stays CGO-free and the
  reproducible-build story stays simple.

**Alternatives considered**:
- **JSON files per run**: simple, but the "new / still / resolved"
  classification (User Story 3) would have to scan every previous
  file. O(N²) on the number of runs. Rejected.
- **BoltDB / `bbolt`**: works, but SQL is a better fit for the
  fingerprinting + cross-run queries the spec implies. Rejected.
- **PostgreSQL / external DB**: violates the "single static binary,
  runs on a stock Linux server with no extra service" model. Rejected.

---

## R-003. CVE feed source

**Decision**: Pluggable adapter behind `internal/cve` with two
first-class sources for v3.0.0 — **NVD JSON 2.0** as the canonical
source, and **OSV** as an alternative. The user selects the source
with `--cve-source=nvd|osv`. Both are open, free, and support
offline caching.

**Rationale**:
- NVD is authoritative, US-government-curated, and free. The JSON
  2.0 API is stable and supports filtering by CPE / keyword.
- OSV.dev is open-source-friendly, has a cleaner schema for package
  ecosystems, and is fast (single REST call per image). Useful as a
  cross-check and as a fallback when NVD rate-limits.
- The feed is opt-in (`--refresh-cve`); the scan runs offline using
  the cached database otherwise. This matches FR-013 and the
  "no ambient telemetry" constraint.

**Alternatives considered**:
- **Trivy DB / Grype DB**: pre-built, curated, ecosystem-rich. But
  Trivy and Grype are themselves Go programs we would either shell
  out to (violates single-binary) or vendor their DBs (extra build
  dependency). Rejected for v3.0.0; revisit if the NVD/OSV path
  proves too slow or too sparse.
- **GHSA (GitHub Security Advisories)**: good coverage but coupled
  to GitHub auth and rate limits, and not the canonical source for
  CVEs outside the GitHub ecosystem. Rejected as a primary source;
  could be added later as a third adapter.

---

## R-004. Package metadata source (security-update detection)

**Decision**: Detect the host's package manager at runtime via a
small dispatch layer in `internal/platform/packagemanager` and adapt
to **apt / dnf / pacman / apk**. No network call is required to *list*
pending updates when local metadata is fresh; the network-refresh is
opt-in.

**Rationale**:
- The four families cover Debian/Ubuntu, Fedora/RHEL, Arch, and
  Alpine — the vast majority of self-hosted Linux targets.
- Local metadata is always available; the network call is only for
  refreshing a stale cache, which matches FR-017 and the
  "opt-in network" model.
- Adding a new family is a single new file in
  `internal/platform/packagemanager/`; the interface is small.

**Alternatives considered**:
- **Snap / Flatpak only**: leaves apt/dnf/pacman/apk unsupported.
  Rejected.
- **Distribution-specific tools only (e.g. `needs-restarting`,
  `unattended-upgrade --dry-run`)**: not portable, fragile. Rejected.

---

## R-005. Privilege elevation

**Decision**: Auto-elevate per-category via the platform's standard
helper — `sudo` on most Linux distributions, `pkexec` where polkit is
the convention. The program batches its elevation needs so a single
successful elevation covers all categories that need it in one scan
(Spec edge case: "multiple elevation prompts in a single scan"). On
elevation failure (decline, wrong password, no TTY, user not in the
elevation group), affected categories are skipped with a clear
message; the scan continues.

**Rationale**:
- Matches the spec Q2 answer (clarifications: privilege model C).
- Batching avoids the "sudo every category" UX disaster and matches
  the spec edge case.
- Each elevated sub-process is the minimum command needed for its
  category; the program does not retain elevated privileges beyond
  the lifetime of that sub-process (FR-018).

**Alternatives considered**:
- **Require pre-elevation (`sudo hostveil`)**: simplest contract,
  but adds friction for casual use; the user has to know to elevate
  the whole tool when only the firewall check needs root. Rejected
  per spec Q2 answer.
- **Skip+warn on missing privileges (clarification option A)**: safer
  but produces a half-blind scan on a stock system; the spec user
  picked the more thorough option. Rejected for v3; the skip+warn
  path remains as the *degraded* behavior when elevation fails.

---

## R-006. CLI framework

**Decision**: `github.com/spf13/cobra` for the command tree and
flag parsing. Subcommands for v3.0.0: `scan`, `fix`, `rollback`,
`explain`, `version`. `--format=json` flag on `scan`, `fix`, and
`rollback` to expose the JSON contract (Spec FR-002: machine-readable
output).

**Rationale**:
- Cobra is the de-facto Go CLI framework; it composes well with
  `pflag` and supports the testability we need for the contract
  tests in `tests/contract/`.
- The CLI-First principle (Constitution II) is satisfied by making
  every check and every fix invokable from the command tree, with
  stdout/stderr separation and a meaningful exit code (0/1/2).

**Alternatives considered**:
- **`urfave/cli`**: works, but Cobra's subcommand model and
  ecosystem (completions, man-page generation) are a better fit for
  a tool that will grow subcommands over v3.x. Rejected.
- **Hand-rolled `flag` parser**: too small for a v3 with this many
  subcommands and shared flags. Rejected.

---

## R-007. Logging

**Decision**: `log/slog` (Go 1.21+ stdlib) with the JSON handler.
Every log line carries `timestamp`, `level`, `component` (the
package that emitted it), and a `scan_run_id` (UUID) so that all log
lines for a single scan can be correlated. The user-visible report
is *not* the log stream: logs go to stderr (or to a file under
`~/.local/share/hostveil/logs/` when `--log-file` is set), and the
human report goes to stdout (Spec FR-004).

**Rationale**:
- Matches Constitution Principle V (Observability & Versioning):
  structured, machine-parseable, with a correlation identifier.
- `slog` is in the standard library, which keeps the dependency
  list short and the build deterministic.

**Alternatives considered**:
- **`go.uber.org/zap`**: faster at high volume, but the v3 scan is
  not a high-volume log producer and `slog` ships with the toolchain.
  Rejected.
- **`logrus`**: in maintenance mode upstream; `slog` is the
  recommended successor. Rejected.

---

## R-008. Report file format

**Decision**: Plain text on stdout and on disk (Spec FR-004). The
text format is human-first, ≤ 120 columns wide, grouped by category
and ordered by severity. A parallel JSON shape is available via
`--format=json` and is the canonical machine-readable form; the text
report is rendered from the same data, not the other way around. The
JSON shape is locked by `tests/contract/report_json_test.go`. No
secrets or credentials ever appear in either output (FR-020); values
are redacted at the producer.

**Rationale**:
- Spec Q3 answer locked the output to "stdout + text file under
  `~/.local/share/hostveil/reports/`".
- Defining the JSON shape first and rendering the text from it keeps
  the two formats in lock-step and gives us a single source of
  truth.

**Alternatives considered**:
- **HTML report**: useful but the v3 user is on a terminal (spec
  says "non-expert" + "simple program"); HTML adds complexity for a
  v3.0 audience. Deferred to a post-v3.0 feature.
- **SARIF**: a great fit for IDE / code-scanning integrations, but
  adds a dependency and is overkill for a v3.0 home-user tool.
  Deferred to a post-v3.0 feature.

---

## R-009. Test architecture

**Decision**: Three layers, mirroring the Constitution's Test-First
and Integration-Testing principles.

- `unit` tests live next to the package they cover (Go convention:
  `foo_test.go` alongside `foo.go`).
- `contract` tests in `test/contract/` lock the public CLI surface
  and the report file formats. They shell out to the built binary
  with a controlled environment and assert on stdout / stderr /
  exit code / file contents.
- `integration` tests in `test/integration/` boot a disposable
  containerized Linux host (built from `test/hostimage/Dockerfile`)
  that is pre-seeded with each in-scope misconfiguration, install
  the `hostveil` binary into it, and run the full scan / fix /
  rollback flow end to end.

**Rationale**:
- Constitution III mandates red-first tests for every check; the
  per-package unit tests are the natural place for that.
- Constitution IV mandates integration tests for new library
  contracts and inter-process interactions; the containerized test
  host is the only way to exercise the real Linux config files,
  Docker socket, sysctl keys, and package manager at the same time.

**Alternatives considered**:
- **Chroot-only test environment**: lighter, but cannot simulate
  Docker and systemd-managed services reliably. Rejected for the
  integration layer; could be used for faster unit-level Linux
  behavior tests where applicable.
- **Mocks for everything**: would let the unit suite run faster,
  but would not satisfy Constitution IV's "real interactions"
  requirement. Mocks are used only for external services (CVE
  feed) inside unit tests; the integration layer is the source of
  truth.

---

## R-010. Determinism and reproducibility

**Decision**: Build script in `scripts/build.sh` runs:

```text
go build -trimpath -buildvcs=false \
  -ldflags "-X main.version=$(git describe --tags --always) \
            -X main.commit=$(git rev-parse HEAD) \
            -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o dist/hostveil ./cmd/hostveil
```

CI then re-runs the build on a known-clean container, hashes the
artifact, and compares against the locally-built artifact's hash. A
mismatch fails the build.

**Rationale**:
- `-trimpath` strips absolute paths from the binary; the rest is
  controlled by `go.sum` and recorded build metadata.
- Embedding the git tag, commit, and build date into the binary
  satisfies Constitution V (semver + observable artifacts) without
  needing a separate metadata file.

**Alternatives considered**:
- **GoReleaser**: a fine tool, but the v3.0.0 release story is a
  single binary; a hand-rolled `scripts/release.sh` is enough for
  the first release and we can adopt GoReleaser later if matrix
  builds (multi-arch, multiple package formats) become necessary.

---

## R-011. Out-of-scope items (explicitly recorded)

These are the items the spec deferred or marked out of scope. They
are listed here so the planning team does not accidentally reintroduce
them as v3.0.0 work:

- **Multi-host management**: single host per invocation.
- **Self-update mechanism**: not in v3.0.0; the user updates
  Hostveil through their distribution's package manager or by
  re-downloading the release artifact.
- **HTML / SARIF reports**: text + JSON only for v3.0.0.
- **v2.5.2 codebase reference**: explicitly forbidden by the spec
  (clarifications, "Version context" assumption).
- **macOS / Windows hosts**: out of scope; program prints
  "unsupported platform" on non-Linux.
- **Cloud-managed services**: out of scope.
- **Real-time continuous monitoring**: scans are on-demand.

---

## R-012. TUI framework

**Decision**: `github.com/charmbracelet/bubbletea` for the Model-Update-
View loop, `github.com/charmbracelet/lipgloss` for styling, and
`github.com/charmbracelet/bubbles` for the list / viewport / help
components. Build-tag-gated with `notui` so the bubbletea dependency
is excluded from headless server builds (FR-031 + SC-010).

**Rationale**:
- bubbletea is the de-facto Go TUI framework; its Model-Update-View
  pattern keeps the TUI testable via `teatest` (captures the rendered
  model after each key event), which is essential for satisfying the
  test-first principle.
- All three Charm libraries share an MIT license and are well-
  maintained; they are the most common choice for production Go TUIs.
- Lipgloss styles gracefully degrade when stderr is not a TTY or
  when `--no-color` is set, which keeps the spec's "no color in
  files" rule honest for any TUI-rendered report.

**Alternatives considered**:
- **`rivo/tview`**: more widget-focused, less idiomatic for an Elm-
  style architecture. Rejected.
- **Hand-rolled `tcell` + raw `lipgloss`**: doable, but the bubble
  ecosystem is the fastest path to a tested, accessible TUI.
  Rejected for v3.0.0; could be revisited if bubbletea's maintenance
  falters.

---

## R-013. Web UI framework

**Decision**: Go standard library `net/http` for the server,
`html/template` for the templates, and a vendored HTMX helper (no
CDN, no remote script at runtime) for the client-side interactivity.
Build-tag-gated with `noweb` (post-v3.0) for users who want to drop
the web surface entirely. v3.0.0 ships the web surface as part of
the default binary.

**Rationale**:
- The web dashboard is a read-mostly single-page UI over the
  findings in `state.db`. A full SPA framework (React, Vue) is
  overkill and pulls in a build pipeline, a node toolchain on the
  build host, and a significant increase in surface area to audit.
- HTMX gives the "click to apply fix" interactivity with one
  ~14 KB vendored file, no client-side state to manage, and no
  client-side secrets to leak. The dashboard's POST actions go
  through the same `hostveil fix` flow as the CLI (FR-027).
- The web surface is bound to `127.0.0.1` by default (FR-025), so
  the attack surface for a network attacker is zero. The non-
  loopback path is gated behind auth + HTTPS.

**Alternatives considered**:
- **React / Vue SPA**: rejected for the audit / build complexity.
- **Go-only server-rendered HTML with form submits**: doable, but
  the dashboard benefits from a few partial-page updates that
  HTMX gives for free without a SPA. Rejected as a worse
  experience for the same security posture.
- **A separate `hostveil-web` binary**: rejected to keep the
  v3.0.0 distribution to a single binary.

---

## R-014. AI provider abstraction

**Decision**: A single Go interface
`type Provider interface { Explain(ctx, Finding, Request) (Response, error); Risk(ctx, Finding, Request) (Response, error); Recommend(ctx, Finding, Request) (Response, error) }`
with two first-class adapters in v3.0.0: a local Ollama adapter
(default) and a cloud Anthropic adapter. All AI code is build-tag-
gated with `noai`; the AI package is excluded from the binary when
the tag is set (SC-010).

**Rationale**:
- The interface is small (three methods, all advisory), which keeps
  adapters focused and auditable.
- Ollama as the default is privacy-positive (no data leaves the
  host), works fully offline, and runs on modest hardware
  (the small models fit on a Raspberry Pi).
- Anthropic is the cloud adapter because it has a clean, well-
  documented Messages API and a permissive terms-of-service for
  the use cases the v3 spec describes (advisory security
  explanations).
- The `noai` build tag is the answer to users who want a v3 with
  zero AI code in the binary — a hard, verifiable boundary.

**Alternatives considered**:
- **OpenAI as the cloud adapter**: rejected because its data-use
  policies (training opt-out) are less aligned with v3's privacy
  posture; Anthropic's "data is not used for training" stance is
  closer to what a v3 user would expect.
- **llama.cpp / ggml native binding**: rejected because it would
  pull in CGO and a heavy model file at build time. The user who
  wants local inference is better served by an Ollama process
  they control.
- **A single "cloud" provider with a config-driven URL**: rejected
  because cloud providers have meaningfully different APIs and
  consent postures; one adapter per provider is clearer.

---

## R-015. AI privacy and redaction

**Decision**: The `internal/ai` package's `redact` sub-package
applies a fixed redaction list to every prompt before it leaves
the host. The list matches the one in `contracts/report.md` (PEM
private keys, named credential fields, URL credentials, AWS access
keys) plus a per-finding whitelist of "safe to send" fields
(category, rule id, severity, sanitized entity references, the
finding's pre-written plain-language description). The cloud path
additionally requires explicit one-time consent that prints the
exact field set to the user (FR-030).

**Rationale**:
- The constitution's "Privacy by default" gate (row 6 in the
  plan's check) is the highest-priority constraint for AI work.
  An outbound prompt that contains a private key is an
  unrecoverable breach; the redaction list is therefore
  conservative and the list itself is locked by a contract test
  in `tests/contract/ai_test.go`.
- The per-finding whitelist keeps the prompt useful (the model
  needs the rule id and severity to produce a useful response)
  while bounding the data the provider ever sees.
- The cloud one-time consent is a hard UX gate: the user sees the
  list of fields, says yes or no, and the choice is recorded in
  the `AIRequest` audit row.

**Alternatives considered**:
- **Send the full finding with on-provider redaction**: rejected
  — by the time the bytes leave the host it is too late to redact
  them, and on-provider redaction is not a guarantee any vendor
  offers.
- **Differential privacy / noise injection**: rejected for v3.0.0
  as adding complexity without a clear attacker model.

---

## R-016. Build-time AI exclusion (noai tag)

**Decision**: All AI code lives under `internal/ai/` and is gated
by the `noai` build tag. A `nop` stub under the same import path
provides the no-op `Provider` interface when the tag is set. The
release pipeline runs `go build -tags noai` and `strings` over
the resulting binary; SC-010's assertion (no `(?i)anthropic|openai|
ollama` literal in the binary) is a CI gate.

**Rationale**:
- The constitution's "no ambient telemetry" and "deterministic
  builds" gates are easier to honor with a hard binary-level
  boundary than with runtime flags. A user who wants v3 with
  zero AI capability should be able to verify that property
  with `strings`.
- The `noai` build is also smaller and faster to build, which
  is useful for distro packagers who want a minimal v3 package.

**Alternatives considered**:
- **Runtime config flag `--disable-ai`**: rejected because the
  code is still in the binary; `strings` would still find the
  provider names. A build-time tag is the only hard boundary.
- **`-tags noai` plus a separate `internal/ai` package built
  with the tag**: rejected as the same idea, framed differently.

---

## R-017. TUI / Web build tag symmetry

**Decision**: As a parallel to `noai`, the TUI is gated by `notui`
and the Web surface is gated by `noweb`. v3.0.0 ships the default
binary (CLI + TUI + Web + AI); the `noai` build is a documented
configuration; `notui` and `noweb` are first-class builds targeted
at headless servers. The default build tag set is the empty set;
a `make build-notui` and `make build-noweb` produce the variants.

**Rationale**:
- Server administrators who deploy `hostveil` over SSH do not
  need the TUI; a TUI binary that fails the TTY check on every
  invocation is wasteful. The `notui` build drops bubbletea and
  ~2 MB of dependency from the binary.
- A `noweb` build is useful for "scan-and-fix only" server
  installations where the web dashboard is never going to be
  opened. The default binary is the right starting point, but
  the smaller variants ship for completeness.

**Alternatives considered**:
- **A single binary with runtime `--mode=cli|tui|web`**: rejected
  because the dependencies are still in the binary, the user's
  security boundary is fuzzier (the TUI code is still there for
  someone to call), and the build-tag pattern is the established
  Go idiom.

---

## R-018. Out-of-scope items (v3.0.0, with this update)

The v3.0.0 release includes CLI + TUI + Web + AI. The following
remain explicitly out of scope and are recorded here so the
planning team does not accidentally reintroduce them:

- **Multi-host management**: single host per invocation.
- **Self-update mechanism**: not in v3.0.0; the user updates
  Hostveil through their distribution's package manager or by
  re-downloading the release artifact.
- **HTML / SARIF reports**: text + JSON only for v3.0.0.
- **v2.5.2 codebase reference**: explicitly forbidden by the spec
  (clarifications, "Version context" assumption).
- **macOS / Windows hosts**: out of scope; program prints
  "unsupported platform" on non-Linux.
- **Cloud-managed services**: out of scope.
- **Real-time continuous monitoring**: scans are on-demand.
- **AI-driven autonomous fixes**: AI is advisory only. Any fix
  that follows an AI recommendation still requires explicit user
  confirmation (FR-032).
- **TUI over the web**: the TUI and the Web are independent
  surfaces; there is no embedded terminal in the Web UI in
  v3.0.0.
- **Web UI multi-tenant auth**: a single token, single user; no
  role-based access control, no per-user audit, no team mode.
