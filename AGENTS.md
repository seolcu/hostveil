# AGENTS.md

Guidance for AI coding agents (Claude Code, OpenCode and Codex all read this file directly; do not add a Claude-specific copy). Rules only. The reasoning behind each lives in the doc comment or test it names, and the history lives in git.

## What this is

Hostveil is a single-binary guided hardening tool for self-hosted Linux servers: it scans a host, merges findings into one 0–100 score, explains them, and applies fixes with preview, backup and rollback. Go 1.26, GPL-3.0, no config file, no cloud.

## Commands

```bash
go build ./cmd/hostveil                                   # produces ./hostveil
go test ./internal/check/ssh -run TestName                # single test
go test ./internal/compose -run FuzzEdit -fuzz FuzzEdit   # fuzz: FuzzEdit, FuzzParse, FuzzParseTrivy, FuzzUnified, FuzzJSON5Edit
go run ./cmd/sitegen                                      # regenerate site/, the counts and the READMEs
scripts/gate.sh                                           # the full CI gate, step by step (-fast skips race and cross-compile)
```

Run `scripts/gate.sh` before every push. Do not hand-chain the steps: `gofmt -l .` exits 0 either way, and a chain hides which step failed.

- golangci-lint must be the **released binary** (gate.sh fetches it). `go run …@v2.12.2` refuses this toolchain and lints nothing.
- If `go version` carries a distro suffix (`go1.26.5-X:nodwarf5`), a local govulncheck skips the standard library. Only CI's result counts then.
- Only if touched: `actionlint` for `.github/workflows/`, `shellcheck` for shell scripts, `goreleaser check` for `.goreleaser.yaml`, and regenerate `scripts/install.sh.sha256` for `install.sh`.

CI also cross-compiles every release target and runs e2e (`.github/workflows/e2e.yml`): the real binary through scan → fix → history → rollback → rescan in a seeded container, plus the individual-only fixes on the runner VM (`scripts/e2e/individual.sh`). Debug e2e scenarios locally with `scripts/e2e/vm.sh run <scenario>` (KVM, `HOSTVEIL_BIN` for your own binary, `HOSTVEIL_E2E_DISTRO=fedora`). A CI round trip per attempt is too slow.

Never run the binary against your own machine. Use the demo VM: `cd demo && ./run.sh up` (see `demo/README.md`; the repo syncs on `up` and `reload` only; `provision` does not sync it).

## Architecture

**One engine, three thin UIs.** `internal/core.Engine` owns scanning, scoring, classification, preview, apply and rollback. CLI, TUI and web only render it. UIs may import `core`, `model`, `internal/ui/theme` and `internal/glyph`, never `internal/fix`, `internal/history`, `internal/check` or `internal/compose` (`internal/ui/uitest.AssertThinUI`).

Flow: `cmd/hostveil/app.go` builds the engine (every checker + `fix.Default()`) → `Engine.Scan` detects `platform.Env`, runs checkers concurrently behind `platform.NewScanCache`, validates and classifies findings, scores, diffs against the last scan, persists.

### Seams

- **`internal/platform`** is the only door to the OS. Inject `CommandRunner`; never call `os/exec` in a checker or fix. Runners must be concurrency-safe. `DefaultRunner` pins `LC_ALL=C` and a default timeout. Any parser that matches words assumes C locale.
- **`internal/check`**: a `Checker` is `Source()` / `Available()` / `Check()` and is strictly read-only. A missing dependency means `Available() = (false, reason)`, which marks the domain Skipped. Test against `internal/check/checktest`; hand-written fakes drift from it.
  - Adding a domain: one package under `internal/check/`, a `model.Source` const plus its row in `sourceDefs` (`internal/model/source.go`, caps must still sum to 100), registration in `cmd/hostveil/app.go` in `AllSources()` order, the domain regex in `internal/docs/findings_test.go`, the README and both `checks.html` files, then `go run ./cmd/sitegen`.
- **`internal/fix`**: a `Fix` is a set of `Action`s.
  - Edit actions carry a **pure** `Transform(in []byte) ([]byte, error)` used by both preview and apply. Keep it pure.
  - Exec actions are argv lists, never a shell.
  - Shape: Auto has exactly one action. Review has ≥1 independent alternatives, and a single-action Review carries a `Warning`.
  - `EffectiveKind` floors any exec fix to Review.
- **`internal/model`** holds pure value types. Build findings with `NewFinding(...)`. Every enum is a table keyed by constant value, never slice position. Wire enums marshal as names and still unmarshal legacy integers; `legacySeverities` keeps every name ever written to a snapshot.
- **`internal/ui/theme`** is the only place a color is written. Never put a hex in `view.go` or `app.css`. Check palette changes against `internal/ui/tui/quantize_test.go`, because SSH sessions render in 256 colours.

### Invariants

- **Remediation is a plain max** over Unset < Auto < Review < Manual < Unavailable, between the checker's declaration and the registered fix (`Engine.classify`). A fixable finding with no registered fix becomes Manual. Every UI path uses the same resolution.
- **Auto means safe unattended**: reversible (a file edit with a checkpoint), cannot sever operator access, and unambiguous. Exec is never Auto. The standard and the declined list are the doc comment on `fix.Default()` in `internal/fix/register.go`, pinned by `TestKnownUnregisteredFindings`.
- **Finding IDs are namespaced** by `Source.String()` (`ssh.rootlogin`, `compose.ds016`). `Finding.Key()` is `source|id|service`.
- **Scoring**
  - Axis caps sum to 100, and scoring renormalizes over domains that ran. A skipped domain is N/A, never 100. `ScoreBreakdown.Applicable` is false when nothing ran, and every UI shows N/A.
  - A cap is a weight. Findings erode an axis multiplicatively, with one High costing half. Repeats of one ID on one axis are damped harmonically. Keep `Score` derived from `remaining`.
  - `RemediationUnavailable` findings are charged in full.
  - `ScoreBreakdown.AfterFixes` is the same function with offered fixes treated as applied. UIs hide it when it equals the score.
- **Severity is urgency**:
  - `high`: reachable now, from off-host, with nothing held.
  - `medium`: needs a foothold, a credential or a local account.
  - `low`: no known path.
  - `high` equals the old Critical ∪ High (`TestTheGateStillMeansWhatItMeant`). Checkers must not enumerate the scale themselves.
- **Applied is not in force.** `Finding.Pending` keeps a finding charged until the change takes effect (`fix.Action.TakesEffectOn`, upgraded only by `VerifyStillPresent`). Use `Finding.Active()` and `IsAutoFixable()`, not `.Fixed` (`internal/docs/pending_test.go`).
- **"Couldn't look" never passes for "nothing there."**
  - `Available()` probes the capability (`platform.DockerReachable`). A binary on `PATH` proves nothing.
  - Partial coverage returns findings plus `check.PartialError`, which marks the domain Degraded. Degraded axes are scored and every UI shows the flag. Total failure is an ordinary error, and the axis is excluded.
  - Report every blind spot with `check.Coverage`. Match with `errors.As`.
  - Exit 0 is not an answer: require `LoadState=loaded` from systemctl.
  - Ask the owning tool for effective layered config (`docker compose config`), and treat an unresolvable merge as a coverage gap.
- **OS gate**: `platform.AuditableOS` is the one place that asks whether this is Linux. The checkers that probe things existing on macOS consult it (`internal/docs/auditableos_test.go`).
- **Write the file that wins.** Resolve layered config precedence before editing (`internal/check/ssh` resolves `Include`; `internal/check/sysctl/origin.go` replays systemd-sysctl order, used by `persistSysctl`). Decline to edit package-owned (`/usr/lib`) or boot (`/run`) files.
- **Validators run before the write.** `fix.Action.VerifyCmd` (with `fix.VerifyPathToken`) runs on both the original and the transformed bytes, and is trusted only if it accepts the original. Every SSH fix carries `sshd -t`.
- **Apply order**
  - Validate → backup (blobs + metadata) → write via `platform.WriteFileAtomic`, keeping ownership.
  - A failed write discards its checkpoint (`applyEdit`). `applyMode` keeps a partial one. `applyExec` records after running.
  - `fix.Action.AfterWrite` commands run after the write. If they fail, the original is restored and the commands rerun.
  - `fix.Action.Irreversible` records no files and cannot roll back.
  - Home-directory paths set `fix.Action.NoFollow`.
- **`Engine.applyMu` serializes** apply, batch, rollback and scan. `ApplyFix` locks; `applyFix` is the unlocked body. `Engine.Current()` returns a clone.
- **Fixes use the uncached runner.** Only checkers go through the scan cache.
- **History** (`internal/history`)
  - Every write is atomic, and metadata is written last.
  - Blobs are verified (`BackedFile.BlobSHA256`) before any restore.
  - `Store.Rollback` refuses when the file's hash matches no checkpoint's `AppliedSHA256`, which means an external edit (`core.IsExternalEdit`).
  - `Store.List` returns `*DamagedError` alongside readable checkpoints (`core.IsIncompleteHistory`) and skips directories with no metadata.
  - Pruning is by count and age (`maxCheckpoints`, `minRetention`), oldest first, by directory name.
- **Config editors**: `internal/compose/edit.go` does text surgery and keeps the yaml.v3 re-encode fallback. `internal/json5` has no fallback (it would delete comments), only replaces existing keys, and is the only JSON5 parser.
- **Dashboard security**: mutating routes are `POST /api/…`, every route needs `Server.token`, and Origin is compared by parsed URL.
- **Dashboard language**: only the web dashboard is translated; the TUI and the CLI stay English. English stays in the code. `internal/ui/web/assets/i18n/<lang>.json` maps it: `messages` for `t("…")` in app.js, `server` for text the engine sends (a `{name}` in a key matches any run of text), `findings` by finding ID. A new UI string, finding or fix sentence needs a row in every catalog (`internal/docs/i18n_test.go`).
- **Elevation**: `cmd/hostveil/elevate.go` re-execs under sudo. The loop guard keys on `SUDO_USER`. `HOSTVEIL_NO_SUDO=1` opts out.
- State lives in `/var/lib/hostveil` as root, `~/.local/share/hostveil` otherwise.
- `internal/ai` is optional and advisory. Everything must work with `ai.Noop`.

## Website

- `site/**/*.html` is generated. Edit `cmd/sitegen/` (`pages.json` is plain text, `templates/*.tmpl`, `content/{en,ko}/`), run `go run ./cmd/sitegen` and commit the output. CSS, JS and `site/assets/` are edited directly.
- The checks page counts, the `data-counted` figures and the README counts (between `<!-- hostveil:counts -->` markers) are computed by `cmd/sitegen/counts.go`. Never type them.
- `site/assets/fonts/` is a Hangul subset made by `scripts/korean-subset.py`. Re-run it after editing Korean copy, after sitegen (`TestEveryKoreanSyllableOnTheSiteHasAGlyph`).
- `scripts/social-preview.py` draws the social card and the README banners, and `scripts/ansi2png.py` renders terminal captures. Re-run them after palette, mark or slogan changes.

## Writing rules (everything: copy, docs, UI text, findings, code comments, tests, commits)

These patterns read as machine-written. They apply to every file in the repository and to commit messages, PR bodies and release notes. `internal/docs/aipatterns_test.go` enforces the mechanical ones; the rest are on the writer.

**Sentence shapes**
- No negative parallelism: "not A but B", "A, not B", "not just A", "not only A but also B", "rather than A", "A instead of B" used as a flourish, "it isn't A. It's B", "less A than B". Say B and give the reason. In Korean: "A가 아니라 B", "A라기보다 B", "단순한 A가 아닌".
- No em dashes (—). Use a period, a comma, a colon or parentheses. An en dash in a number range (0–100) is fine, and so is a lone dash meaning "none" in a table cell.
- No reflexive triads (three adjectives, three parallel clauses) when one or two would do.
- No trailing "-ing" commentary that rates the sentence before it ("…, ensuring that…", "…, highlighting…", "…, making it…").
- No copula dodging: write "is" in place of "serves as", "stands as", "functions as", "acts as". Korean: "기능합니다", "역할을 합니다" → "입니다".
- No metaphor, simile or personification to explain a mechanism ("a one-way door", "a medicine label", "the file wins", "the score was crediting"). Name the thing and what it does.
- No rhetorical questions answered in the next sentence, and no "The answer: …" reveals.
- No closing summaries ("Overall,", "In short,", "In summary,", "The upshot", 결론적으로, 종합하면, 요컨대) and no moralising last line.

**Words**
- English: *deliberately, on purpose* (write "intentionally" only where someone's intent is the subject), *honest(ly), quietly, plainly, genuinely, truly, actually* (as emphasis), *outright, precisely, load-bearing, crucial, pivotal, vital, key* (adjective), *robust, seamless, powerful, comprehensive, leverage, delve, landscape, testament, underscore, showcase, foster, notably, worth noting, it's important to note, the point is, here's the thing*, a rhetorical *nobody* or *no one*.
- Korean: 일부러, 정직하게, 솔직히, 조용히, 사실상(강조로), 핵심은, 짚어 둘 만합니다, 주목할 만한, 이처럼, 결론적으로, 종합하면.

**Formatting**
- Headings are noun phrases ("Measured results"). A sentence or a question ("Does it actually work?") is not a heading. Use sentence case.
- Do not enlarge or bold a number to make it impressive. Numbers sit in the sentence at body size; a table is fine.
- Bold is for a term being defined or a UI label, at most once per paragraph. No bold run-in labels on every list item.
- No emoji in prose, headings or list bullets.

**Write Korean directly in Korean; do not translate from English.** Use 합니다체 throughout. Use short sentences and do not stack clauses. Do not open with 그리고/그런데. `당신` is fine where the sentence is about the reader. FAQ answers state the answer directly. Avoid subjectless passives (~이 요구됩니다, ~이 강조됩니다) and abstract nouns where a concrete one exists.

## Releasing

Cut by hand. The tag starts `.github/workflows/release.yml`. Release only when all of these hold:

1. `origin/main` passes `scripts/gate.sh` at the exact commit.
2. There is at least one user-visible change since the last tag.
3. Nothing on main is half-finished.
4. The version follows from the commit subjects: any `feat` means minor, otherwise patch. A **major bump only on a human's explicit word.**

Steps:

- Write the entry in both `CHANGELOG.md` and `CHANGELOG.ko.md` (`### Features`/`### Bug Fixes`, `### 새 기능`/`### 버그 수정`) and land it through a PR. Move shipped roadmap items in both languages' `roadmap.html` in the same PR.
- Write the release notes in English, then the Korean inside `<details>`. Images go under `site/assets/releases/<version>/`.
- Create the release:

```bash
gh release create vX.Y.Z --target "$(git rev-parse origin/main)" --title vX.Y.Z --notes-file notes.md
```

- `--target` is mandatory. Never move or delete a published tag.
- If Actions cannot allocate runners, create the release with `--draft` (no tag is created) and publish it later with `gh release edit vX.Y.Z --draft=false`.

## Pull requests

- **Titles are conventional and become the squashed commit subject**, which drives the version and the changelog. Put the component in the scope: `fix(check): …`. The scope must be one of `.github/workflows/pr-title.yml`'s allowlist (package names, never paths like `check/ssh`).
- Land a PR before starting the next one that touches the same files. To move a stacked branch, use `git rebase --onto origin/main <old base tip>`.
- The version string lives only in `cmd/hostveil/main.go` and is overwritten by goreleaser ldflags.
- Repository topics come from `CITATION.cff` `keywords` and are applied by hand with `gh repo edit`. The social preview image (`site/assets/social-preview.png`) is uploaded by hand in Settings.

## Measurement harness

`scripts/measure/run.sh` measures Hostveil with Lynis, the CIS Docker Benchmark and a TCP scan, before and after fixes, restarts, Review fixes and rollback. `-c` runs `check.py`; `-C` runs the CIS control. It edits the host it runs on, so use a VM. Rollback fidelity is judged against hashes taken before the fixes, on paths the scan named.

Committed results live in `docs/measurements/`. Never edit them. Site figures are pinned to them by `internal/docs/measurements_test.go`; register new publication profiles there.
