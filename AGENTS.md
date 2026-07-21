# AGENTS.md

Guidance for AI coding agents working in this repository. OpenCode and Codex read this file directly; Claude Code does not, so it reads it through the `@AGENTS.md` import in `CLAUDE.md` — keep that file, it is the only thing wiring the two together.

`internal/docs/agents_test.go` checks the mechanical claims below against the code — that referenced paths and symbols exist, that the checker count and lint list match. Reword the prose freely; renaming something this file names will fail the build until the sentence is updated too.

## What this is

hostveil is a single-binary guided hardening tool for self-hosted Linux servers: it scans a host, merges findings into one 0–100 score, explains them in plain language, and applies fixes with preview, backup, and rollback. Go 1.26, GPL-3.0, no config file, no cloud.

## Commands

```bash
go build ./cmd/hostveil     # produces ./hostveil
go test ./...
go test -race ./...         # what CI runs
go test ./internal/check/ssh -run TestName        # single test
go test ./internal/compose -run FuzzEdit -fuzz FuzzEdit   # fuzz targets: FuzzEdit, FuzzParse, FuzzParseTrivy
scripts/bench.sh            # benchmarks (there is intentionally no Makefile)
go run ./cmd/sitegen        # regenerate site/ — required whenever cmd/sitegen/ changes
```

Full CI gate, run all of these before sending a change:

```bash
go build ./... && go vet ./... && gofmt -l . && go mod tidy && go test -race ./...
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go run ./cmd/sitegen && git diff --exit-code site/
(cd scripts && sha256sum -c install.sh.sha256)   # regenerate the .sha256 if install.sh changed
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12   # only if you touched .github/workflows/
```

Lint config (`.golangci.yaml`) enables only staticcheck, ineffassign, misspell.

### Running it for real

The binary builds and tests everywhere, but only *runs* meaningfully on Linux with docker/ssh/ufw present. Don't run it against your own machine — use the Vagrant demo VM, which rsyncs your working tree in and rebuilds:

```bash
cd demo && ./run.sh up      # then: ./run.sh scan | web | shell | reset | halt
```

The repo syncs on `up`/`reload` but **not** on `provision` — re-sync after editing code. See `demo/README.md` and `docs/DEVELOPMENT.md`.

## Releasing

Releases are automated — **never push a `v*` tag by hand.** That is how `v3.0.0` ended up published from a commit that was never on main, pointing every `install.sh` user at abandoned code. A tag ruleset now rejects it anyway.

release-please watches main and keeps a release pull request open with the next version and the changelog diff. Edit that pull request if the version is wrong, then merge it: merging creates the tag and the GitHub release, and goreleaser attaches the archives, checksums, SBOMs, and provenance attestation. Config is `release-please-config.json` and `.release-please-manifest.json` — the manifest is the version of record, not any git tag.

**Version numbers come from pull request titles.** Merges to main are squashed and the title becomes the commit subject, so the title must be conventional: `feat(site): …`, `fix(model): …`. Put the component in the *scope*, never the type — `site:` and `check/cve:` parse as types nobody has a bump rule for, so the change lands as a patch and disappears from the changelog.

The scope is not free text. `.github/workflows/pr-title.yml` accepts only `core`, `model`, `check`, `cve`, `compose`, `fix`, `platform`, `history`, `ai`, `ui`, `tui`, `web`, `cmd`, `sitegen`, `site`, `demo`, `docs`, `install`, `ci`, `release`, `deps`. A path-shaped scope like `check/ssh` is rejected and the pull request cannot merge until the title is edited, so name the package, not the subpackage: a change to `internal/check/ssh` is `fix(check):`. Commits on your own branch are unconstrained. There are no `!`/`BREAKING CHANGE` markers anywhere in this repo's history, so a major bump is still a human decision made by editing the release pull request.

The version string lives in exactly one place, `cmd/hostveil/main.go`, and is overwritten at build time by goreleaser's ldflags. Nothing in the release pipeline rewrites Go source, and `scripts/install.sh` resolves the version at runtime rather than being stamped — keep it out of release-please's `extra-files`, or its pinned checksum stops matching.

## Architecture

The central rule: **one engine, three thin UIs.** `internal/core.Engine` owns all scanning, scoring, classification, preview, apply, and rollback. CLI, TUI, and web are rendering layers over it, so a fix applied anywhere behaves identically and is reversible anywhere.

This is enforced structurally: `internal/ui/tui/layering_test.go` and `internal/ui/web/layering_test.go` parse imports and fail if production UI code imports `internal/fix`, `internal/history`, `internal/check`, or `internal/compose`. UIs may import only `core` and `model`. (v2's duplicated-fix-logic failure is what these tests exist to prevent.)

Flow: `cmd/hostveil/app.go` builds the one engine (all nine checkers + `fix.Default()`) → `Engine.Scan` detects `platform.Env`, runs the checker registry concurrently, validates and classifies findings, scores, diffs against the last saved scan, persists.

### Key seams

- **`internal/platform`** — the only door to the OS. `CommandRunner` (Run/LookPath) is injected everywhere, so checkers and fixes are unit-tested against a fake runner with no real host. Never call `os/exec` directly in a checker or fix.
- **`internal/check`** — `Checker` is `Source()` / `Available()` / `Check()`. Checkers are strictly read-only. A missing dependency returns `Available() = (false, reason)` → domain recorded **Skipped**, never an error; a panic in one checker degrades only that domain. Adding a detection domain = one package under `internal/check/` implementing `Checker`, registered in `app.go`, plus a scoring axis. A new `model.Source` needs four edits in `internal/model/source.go`, not three: the const, the `String()` case, the `AllSources()` entry, **and the upper bound of `Valid()`** — that last one is a range check, and forgetting it makes every finding from the new domain fail `Validate()` and vanish after the scan, so the domain reports clean rather than reporting nothing.
- **`internal/fix`** — a `Fix` is a set of `Action`s. Edit actions carry a **pure `Transform(in []byte) ([]byte, error)`** — bytes in, bytes out, no disk writes — used by *both* preview (diff only) and apply (write). Preserve that purity; it's what makes previewing safe. Exec actions carry argv lists (no shell). `Validate` enforces shape: Auto = exactly 1 action, Review = ≥2 *independent alternatives* (not sequential steps).
- **`internal/model`** — pure value types, no I/O. Build findings via `NewFinding(id, title, severity, source, remediation, opts...)`; required args make zero-value footguns unrepresentable, and `Validate()` runs over every finding post-scan so malformed ones never reach a UI.

### Invariants worth knowing

- **Remediation is settled by whichever source is more cautious.** `Engine.classify` resolves the checker's declared `Remediation` against the registered fix's `Kind` and takes the stricter (`RemediationKind` is ordered Auto < Review < Manual < Unavailable). The registry decides *whether a fix exists* — a fixable-but-unregistered finding is demoted to Manual, so a UI can never show a fix button that leads nowhere. The checker decides *how much human judgment it needs*, and a fix registered as Auto (a statement about its shape: one mechanical action) can't talk it down.
- **Auto means safe to apply unattended**, which requires all of: reversible (a file edit, so apply writes a restore checkpoint — exec actions are never Auto), recoverable in practice (nothing that can sever the operator's own access to the host, even if the edit itself reverts cleanly), and unambiguous (one correct remediation that can't break a legitimate config). Anything else is Review, or Manual when there is no safe action at all. The full standard, and the list of findings deliberately left unfixed with reasons, is the doc comment on `fix.Default()` in `internal/fix/register.go`; `TestKnownUnregisteredFindings` pins it.
- **Finding IDs are namespaced by `Source.String()`**: `ssh.rootlogin`, `compose.ds016`, `cve.*`. The fix registry matches exact IDs or globs against these. `Finding.Key()` = `source|id|service`.
- **Scoring renormalizes over domains that ran.** `model.ScoreReport`'s axis caps sum to 100; a skipped domain (e.g. no Trivy) is marked N/A and excluded rather than scored 100, so a partial scan is never a falsely perfect result. Adding a domain means adding an axis to `axisDefs` and rebalancing the caps.
- **A cap is a weight, never a threshold.** Findings erode an axis *multiplicatively* — each takes a share of what is left (`remaining *= 1 - weight(f)`), anchored on one Critical costing half. Summing severities and clamping, the model this replaced, meant two Criticals exhausted most axes and every finding after that was free: a host with 27 container findings scored the same as one with 3, and both CVE and container sat pinned at 0. Keep `Score` derived from `remaining` rather than from the rounded `Penalty`, or a small-cap axis loses its resolution.
- **A score you can't improve by doing everything right measures nothing.** `RemediationUnavailable` findings are weighted down (`unavailableRelief`) because every image ships CVEs with no upstream patch; charging those in full pins the axis at 0 for a perfectly maintained host. They are not free either — the risk is real, and zero would be its own lie.
- **A checker must never let "I couldn't look" pass for "nothing there."** The two score identically and mean opposite things, which is how a non-root scan once reported a perfect CVE score. So: `Available()` probes the *capability*, not just the binary (`platform.DockerReachable`, not `Has(r, "docker")`); a checker that covered only part of its ground returns its findings plus a `check.PartialError` (→ `ScanDegraded`); one that covered none returns an ordinary error (→ `ScanError`, axis excluded). Degraded axes *are* scored, flagged via `ScoreAxis.Degraded`, and every UI must render that flag — a total failure dressed as Degraded would restore the false 100 by another route.
- **Apply order is always backup → write → checkpoint.** `applyEdit` refuses to write if the backup fails. Exec fixes have no rollback checkpoint (nothing file-backed), only a history record.
- **Rollback declines rather than clobbers.** The checkpoint records the SHA-256 of what the fix wrote (`Checkpoint.AppliedSHA256`), and `Store.Rollback` refuses if the file no longer hashes to something *some* checkpoint recorded writing — rollback keeps no backup of its own, so overwriting an operator's later edits is unrecoverable. The test is membership across all checkpoints, not equality with this one: two fixes to the same file (`fix --all` over one compose file) legitimately leave the second fix's content in place. `core.IsExternalEdit` exists so UIs can tell a declined rollback from a failed one without importing `internal/history`, which the layering tests forbid.
- **`internal/compose/edit.go` does minimal text-edit YAML surgery** so a one-line change stays a one-line diff, then verifies the result round-trips byte-identically through yaml.v3 and falls back to a full re-encode otherwise. Correctness never depends on the text surgery — keep that fallback.
- **Auto-elevation**: `cmd/hostveil/elevate.go` re-execs under sudo for root-benefiting commands. `HOSTVEIL_NO_SUDO=1` opts out (scripts/CI); `HOSTVEIL_ELEVATED=1` is the re-exec loop guard. `version`/`help` never prompt.
- State lives in `/var/lib/hostveil` as root, `~/.local/share/hostveil` otherwise.

## Website

`site/**/*.html` is **generated — never hand-edit it.** Source of truth is `cmd/sitegen/`: `pages.json` (metadata, **plain text** — the generator HTML-escapes it, so write `Fixing & rollback`), `templates/*.tmpl`, `content/{en,ko}/` (raw HTML fragments). Regenerate with `go run ./cmd/sitegen` and commit the output; CI fails if `site/` drifts. CSS/JS and `site/assets/` are *not* generated — edit directly.

## AI

`internal/ai` is optional and strictly advisory (local Ollama, `explain --ai`). It never applies changes; every score, explanation, and fix must work with `ai.Noop`.
