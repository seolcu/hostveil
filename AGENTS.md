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

Releases are cut by hand — by a maintainer or by an agent working in this repo — and the tag is what starts the pipeline. There is no release-please and no release pull request.

It used to work the other way, and the reason it does not is worth keeping: release-please opened the release pull request with the default `GITHUB_TOKEN`, and GitHub does not start workflow runs for events created by that token. So the release pull request carried **no CI checks at all**, the `main` ruleset requires `build` and `lint`, and every single release therefore had to be forced through an admin bypass. That is not automation; it is a manual step wearing a costume.

### When to cut a release

Release when **all** of these hold. If any is false, say so and stop rather than releasing anyway.

1. `origin/main` passes the full CI gate below, run locally, at the exact commit being tagged.
2. There is at least one user-visible change since the last tag. A release containing only refactors, test changes, or CI edits is noise for everyone who has to read the changelog.
3. Nothing on main is known-broken or half-finished — no feature landed in pieces with the rest still open.
4. The version follows from the conventional-commit subjects since the last tag, computed and not guessed: any `feat` → **minor**, otherwise → **patch**.

A **major** bump is never automatic and never an agent's decision. It requires a human saying so explicitly, in words, for that release.

### How to cut one

```bash
git checkout main && git pull
go build ./... && go vet ./... && gofmt -l . && go mod tidy && go test -race ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go run ./cmd/sitegen && git diff --exit-code site/

git log --oneline "$(git describe --tags --abbrev=0)"..main   # what is going in
```

Write the changelog entry into `CHANGELOG.md` — grouped `### Features` / `### Bug Fixes`, newest version first, matching the existing shape — and land it on main through a normal pull request. Then create the release, which creates the tag:

```bash
gh release create v3.2.0 --target "$(git rev-parse origin/main)" --title v3.2.0 --notes-file notes.md
```

Pushing that tag starts `.github/workflows/release.yml`, which re-runs the full gate against the tagged commit, refuses the tag if it is not an ancestor of `origin/main`, and then lets goreleaser attach the archives, checksums, SBOMs, and provenance attestation. If any of that fails the release is demoted to a draft, which keeps `install.sh` users on the last good version — it resolves the version by following the `/releases/latest` redirect, and a draft is not "Latest".

`--target` is not optional. **`v3.0.0` was published from a commit that was never on main**, pointing every `install.sh` user at abandoned code. The `release-tags` ruleset does *not* prevent a repeat: it forbids **updating and deleting** a `v*` tag, not creating one on the wrong commit. The `verify-on-main` job in the release workflow is what actually blocks that now.

Never move or delete a published tag. That the ruleset does enforce, and installers and the provenance attestation both assume a tag is immutable.

**Version numbers come from pull request titles.** Merges to main are squashed and the title becomes the commit subject, which is the only record of what a change was when the release is cut. The title must be conventional: `feat(site): …`, `fix(model): …`. Put the component in the *scope*, never the type — `site:` and `check/cve:` parse as types with no bump rule, so the change reads as a patch and drops out of the changelog.

The scope is not free text. `.github/workflows/pr-title.yml` accepts only `core`, `model`, `check`, `cve`, `compose`, `fix`, `platform`, `history`, `ai`, `ui`, `tui`, `web`, `cmd`, `sitegen`, `site`, `demo`, `docs`, `install`, `ci`, `release`, `deps`. A path-shaped scope like `check/ssh` is rejected and the pull request cannot merge until the title is edited, so name the package, not the subpackage: a change to `internal/check/ssh` is `fix(check):`. Commits on your own branch are unconstrained.

The version string lives in exactly one place, `cmd/hostveil/main.go`, and is overwritten at build time by goreleaser's ldflags. Nothing in the release pipeline rewrites Go source, and `scripts/install.sh` resolves the version at runtime rather than being stamped. The git tag is the version of record.

## Architecture

The central rule: **one engine, three thin UIs.** `internal/core.Engine` owns all scanning, scoring, classification, preview, apply, and rollback. CLI, TUI, and web are rendering layers over it, so a fix applied anywhere behaves identically and is reversible anywhere.

This is enforced structurally: `internal/ui/tui/layering_test.go` and `internal/ui/web/layering_test.go` parse imports and fail if production UI code imports `internal/fix`, `internal/history`, `internal/check`, or `internal/compose`. UIs may import only `core` and `model`. (v2's duplicated-fix-logic failure is what these tests exist to prevent.)

Flow: `cmd/hostveil/app.go` builds the one engine (all nine checkers + `fix.Default()`) → `Engine.Scan` detects `platform.Env`, runs the checker registry concurrently, validates and classifies findings, scores, diffs against the last saved scan, persists.

### Key seams

- **`internal/platform`** — the only door to the OS. `CommandRunner` (Run/LookPath) is injected everywhere, so checkers and fixes are unit-tested against a fake runner with no real host. Never call `os/exec` directly in a checker or fix. Implementations must be safe for concurrent use: checkers run together and the CVE checker scans images in parallel, and `platform.ScanCache` wraps the runner for the duration of a scan.
- **`internal/check`** — `Checker` is `Source()` / `Available()` / `Check()`. Checkers are strictly read-only. A missing dependency returns `Available() = (false, reason)` → domain recorded **Skipped**, never an error; a panic in one checker degrades only that domain. Adding a detection domain = one package under `internal/check/` implementing `Checker`, registered in `app.go`, plus a scoring axis. A new `model.Source` needs four edits in `internal/model/source.go`, not three: the const, the `String()` case, the `AllSources()` entry, **and the upper bound of `Valid()`** — that last one is a range check, and forgetting it makes every finding from the new domain fail `Validate()` and vanish after the scan, so the domain reports clean rather than reporting nothing.
- **`internal/fix`** — a `Fix` is a set of `Action`s. Edit actions carry a **pure `Transform(in []byte) ([]byte, error)`** — bytes in, bytes out, no disk writes — used by *both* preview (diff only) and apply (write). Preserve that purity; it's what makes previewing safe. Exec actions carry argv lists (no shell). `Validate` enforces shape: Auto = exactly 1 action, Review = ≥2 *independent alternatives* (not sequential steps).
- **`internal/model`** — pure value types, no I/O. Build findings via `NewFinding(id, title, severity, source, remediation, opts...)`; required args make zero-value footguns unrepresentable, and `Validate()` runs over every finding post-scan so malformed ones never reach a UI.
- **`internal/ui/theme`** — the only place a color is written down. It holds every palette as twelve semantic roles, and both UIs read from it: the TUI builds lipgloss styles via `newStyles`, and the dashboard's `/themes.css` and `/theme.js` are generated by `theme.CSS` and `theme.JS` at request time. The palettes used to be duplicated by hand in `view.go` and `app.css`, each claiming in a comment to match the other; do not put a hex back into either file. The package is pure data and string formatting — no lipgloss, no `image/color` — which is what lets the web UI depend on it. The remembered choice (`theme.Load`/`Save`) is a one-line file in the state directory, resolved in `cmd/hostveil/theme.go` because `internal/ui` may not import `internal/history`.

### Invariants worth knowing

- **Remediation is settled by whichever source is more cautious.** `Engine.classify` resolves the checker's declared `Remediation` against the registered fix's `Kind` and takes the stricter (`RemediationKind` is ordered Auto < Review < Manual < Unavailable). The registry decides *whether a fix exists* — a fixable-but-unregistered finding is demoted to Manual, so a UI can never show a fix button that leads nowhere. The checker decides *how much human judgment it needs*, and a fix registered as Auto (a statement about its shape: one mechanical action) can't talk it down.
- **Auto means safe to apply unattended**, which requires all of: reversible (a file edit, so apply writes a restore checkpoint — exec actions are never Auto), recoverable in practice (nothing that can sever the operator's own access to the host, even if the edit itself reverts cleanly), and unambiguous (one correct remediation that can't break a legitimate config). Anything else is Review, or Manual when there is no safe action at all. The full standard, and the list of findings deliberately left unfixed with reasons, is the doc comment on `fix.Default()` in `internal/fix/register.go`; `TestKnownUnregisteredFindings` pins it.
- **Finding IDs are namespaced by `Source.String()`**: `ssh.rootlogin`, `compose.ds016`, `cve.*`. The fix registry matches exact IDs or globs against these. `Finding.Key()` = `source|id|service`.
- **Scoring renormalizes over domains that ran.** `model.ScoreReport`'s axis caps sum to 100; a skipped domain (e.g. no Trivy) is marked N/A and excluded rather than scored 100, so a partial scan is never a falsely perfect result. Adding a domain means adding an axis to `axisDefs` and rebalancing the caps.
- **A cap is a weight, never a threshold.** Findings erode an axis *multiplicatively* — each takes a share of what is left (`remaining *= 1 - weight(f)`), anchored on one Critical costing half. Summing severities and clamping, the model this replaced, meant two Criticals exhausted most axes and every finding after that was free: a host with 27 container findings scored the same as one with 3, and both CVE and container sat pinned at 0. Keep `Score` derived from `remaining` rather than from the rounded `Penalty`, or a small-cap axis loses its resolution.
- **A score you can't improve by doing everything right measures nothing.** `RemediationUnavailable` findings are weighted down (`unavailableRelief`) because every image ships CVEs with no upstream patch; charging those in full pins the axis at 0 for a perfectly maintained host. They are not free either — the risk is real, and zero would be its own lie.
- **A checker must never let "I couldn't look" pass for "nothing there."** The two score identically and mean opposite things, which is how a non-root scan once reported a perfect CVE score. So: `Available()` probes the *capability*, not just the binary (`platform.DockerReachable`, not `Has(r, "docker")`); a checker that covered only part of its ground returns its findings plus a `check.PartialError` (→ `ScanDegraded`); one that covered none returns an ordinary error (→ `ScanError`, axis excluded). Degraded axes *are* scored, flagged via `ScoreAxis.Degraded`, and every UI must render that flag — a total failure dressed as Degraded would restore the false 100 by another route.
- **Apply order is always backup → write → checkpoint.** `applyEdit` refuses to write if the backup fails. Exec fixes have no rollback checkpoint (nothing file-backed), only a history record. The write itself goes through `writeFileAtomic` — temp file beside the target, then rename — because `os.WriteFile` truncates first, and a crash between truncate and write leaves a zero-length `sshd_config` whose backup you now need SSH to reach. `preserveOwner` carries uid/gid across the rename; hostveil runs as root, so skipping it would hand the operator's own compose file to root.
- **One fix at a time, and a scan is a fix for this purpose.** `Engine.applyMu` serializes apply, batch, rollback, and scan. `applyEdit` is a read-modify-write and the dashboard serves concurrently, so without it two fixes to one compose file each read the original and the later write erased the earlier one — while both checkpoints recorded success and both findings were marked Fixed. `ApplyFix` takes the lock and `applyFix` is the unlocked body, because `ApplyBatch` loops and `sync.Mutex` is not reentrant.
- **`Engine.Current()` returns a snapshot, not a view.** `Report` is a struct but `Findings` is a slice, so returning it by value shared the backing array that `markFixed` writes into — `go test -race` caught it as a write in `markFixed` against `json.Encoder` in the dashboard's `/api/result`. It clones.
- **Checkers are read-only, so the scan runs them behind one cache.** `Engine.Scan` wraps the runner in `platform.NewScanCache`, which single-flights identical commands for that scan. Several checkers independently want the same facts (compose and CVE both enumerate projects and inspect standalone containers; ports re-probes the firewall), and each ran twice, concurrently. Fixes deliberately use the *uncached* `e.runner`: an exec fix mutates the host, and a cached result would mean the second `ufw allow` silently never happened. A `CommandRunner` must therefore be concurrency-safe.
- **Checkpoints are capped, oldest-first (`maxCheckpoints`).** They are backups, so the cap is far looser than `maxScans` and must clear whatever one `fix --all` can produce — pruning a checkpoint moments after writing it makes a fix unrollbackable the instant it is applied. Oldest-first is load-bearing for the rule below: the entry that matters for a path is the newest one, so trimming the other end would make an untouched file look edited. Pruning reads directory names only; going through `List()` would re-parse every checkpoint on every applied fix.
- **Rollback declines rather than clobbers.** The checkpoint records the SHA-256 of what the fix wrote (`Checkpoint.AppliedSHA256`), and `Store.Rollback` refuses if the file no longer hashes to something *some* checkpoint recorded writing — rollback keeps no backup of its own, so overwriting an operator's later edits is unrecoverable. The test is membership across all checkpoints, not equality with this one: two fixes to the same file (`fix --all` over one compose file) legitimately leave the second fix's content in place. `core.IsExternalEdit` exists so UIs can tell a declined rollback from a failed one without importing `internal/history`, which the layering tests forbid.
- **`internal/compose/edit.go` does minimal text-edit YAML surgery** so a one-line change stays a one-line diff, then verifies the result round-trips byte-identically through yaml.v3 and falls back to a full re-encode otherwise. Correctness never depends on the text surgery — keep that fallback.
- **The dashboard's routes name their methods, and every route needs the token.** `internal/ui/web` binds to loopback and checks the Host header, but that stops the network, not the other accounts on the machine — and `serve` auto-elevates, so the dashboard applies fixes as root. Two things follow. Mutating routes are registered as `POST /api/…`: the guard used to check the origin of POSTs only while handlers ignored the method, so a cross-origin `<img src=".../api/fix/all">` applied every Auto fix on the host. And `Server.token` (in the printed URL, then a `SameSite=Strict` cookie) gates everything, so a local unprivileged user cannot curl root into editing files. Origin comparison parses the URL — prefix-trimming credited `http://127.0.0.1:8787.evil.example.com`.
- **Auto-elevation**: `cmd/hostveil/elevate.go` re-execs under sudo for root-benefiting commands. `HOSTVEIL_NO_SUDO=1` opts out (scripts/CI); `HOSTVEIL_ELEVATED=1` is the re-exec loop guard. `version`/`help` never prompt.
- State lives in `/var/lib/hostveil` as root, `~/.local/share/hostveil` otherwise.

## Website

`site/**/*.html` is **generated — never hand-edit it.** Source of truth is `cmd/sitegen/`: `pages.json` (metadata, **plain text** — the generator HTML-escapes it, so write `Fixing & rollback`), `templates/*.tmpl`, `content/{en,ko}/` (raw HTML fragments). Regenerate with `go run ./cmd/sitegen` and commit the output; CI fails if `site/` drifts. CSS/JS and `site/assets/` are *not* generated — edit directly.

## AI

`internal/ai` is optional and strictly advisory (local Ollama, `explain --ai`). It never applies changes; every score, explanation, and fix must work with `ai.Noop`.
