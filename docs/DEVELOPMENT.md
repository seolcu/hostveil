# Development

This is the contributor guide for hostveil. It covers the local
workflow, the test layout, the conventions you have to follow,
and the things that will burn you if you do not read `AGENTS.md`
first.

## Local workflow

```bash
go build -o hostveil ./cmd/hostveil/
./hostveil                 # TUI; auto re-execs via sudo
./hostveil serve           # Web UI on 127.0.0.1:8787
./hostveil serve --fixture test/e2e/fixtures/mock-snapshot.json --addr 127.0.0.1:8787
```

A single `main` package at `cmd/hostveil/`. No Makefile. No code
generation. The frontend has no build chain. `app.js` and
`app.css` are served as-is via `//go:embed assets/*`.

## Build and verify

```bash
gofmt -l .                          # must print nothing
go build ./...
go vet ./...
go test -race ./...
```

E2E browser tests (require Node.js 20+ and Playwright):

```bash
go build -o hostveil-e2e ./cmd/hostveil/
cd test/e2e
npm ci
npx playwright install chromium     # one-time
npx playwright test
rm -f ../hostveil-e2e .e2e-server-pid .e2e-kill.sh
```

Installer tests (require Docker):

```bash
bash scripts/test-install.sh
```

## Layout

```
cmd/hostveil/             main package
internal/
  domain/                 types, scoring, scan progress
  scan/                   single-tool dispatcher
  trivy/                  Trivy adapter
  lynis/                  Lynis adapter
  composeaudit/           native compose audit
  compose/                YAML AST editing
  fix/                    fix registry and actions
  history/                checkpoints and scan history on disk
  tui/                    Bubble Tea v2 UI
  web/                    embedded HTTP server and assets
test/
  e2e/                    Playwright specs
```

Each `internal/*` package has its own `_test.go` next to the
source. Run the package tests directly:

```bash
go test ./internal/fix/...
go test -race ./internal/...
```

## Conventions

These are the conventions the codebase actually uses. If you are
adding code, follow them. If you are editing existing code that
violates them, fix it.

### Go
- `gofmt` formatting. No exceptions.
- Comments on every exported symbol.
- Errors are wrapped with `fmt.Errorf("context: %w", err)`.
- No `panic` outside of `init`.
- Goroutines that write to `domain.ScanProgress` go through
  the type's mutex, never directly.
- The TUI's model is taken by value in `Update` (Bubble Tea v2
  pattern). Anything you need to mutate from a background
  goroutine goes through `m.send(msg)`, so the program loop
  applies it.
- Cross-platform shell scripts use `command -v` (not `which`).
  Install commands check for the package manager and fall back
  to a binary download for both `trivy` and `lynis`.

### Fix registry
- Read `AGENTS.md#remediationkind-classification-rules` before
  adding a new fix. The two design rules that get broken the
  most:
  - **Review = alternatives, not stages.** A multi-action
    `Review` fix must offer independent alternatives the user
    can mix and match, not sequential steps that the user has
    to apply in order.
  - **A fix reporting `success=true` must have made the
    change.** Use `set -e` in shell scripts. Use `|| true`
    only for best-effort service start in containers without
    an init system.

### Web UI
- The frontend has no build chain. Do not introduce one. Plain
  ES2020+ JavaScript, hand-rolled template strings.
- Every value rendered into `innerHTML` must be HTML-escaped.
  The shared helper is `escapeHTML(...)`. Browser-decoded
  `data-*` attribute values must be re-escaped on read, since
  the browser has already done entity-decoding once.
- Modal overlays are `position: fixed` divs appended to
  `document.body`. They are styled with the same theme tokens as
  the main UI.

### Tests
- Unit tests live next to the source. Integration tests
  (`internal/web`, `cmd/hostveil`) hit the public HTTP API.
- E2E tests live in `test/e2e/specs/`. Each spec file describes
  one user-visible scenario.
- Use `t.TempDir()` for any test that touches the filesystem.
- `httptest.NewServer` is fine for HTTP tests. Do not start a
  real listener.
- For tests that need to inject findings, use the `Register`
  API on `fix.Registry` directly. Do not mock out the scanner.

#### Fuzz tests
- The three parsers — `internal/lynis`, `internal/trivy`,
  `internal/compose` — have Go fuzz tests in
  `*_fuzz_test.go` next to the source. The fuzz targets are
  the public parsing entry points that take untrusted input:
  - `internal/lynis`: `parseEntry`, `parseManualEntry`,
    `parseExceptionEntry`, `parseReportFile`.
  - `internal/trivy`: `decodeTrivyJSON`, `parseSeverity`,
    `sanitizeCommandOutput`.
  - `internal/compose`: `Open` (the YAML entry point) and
    `yaml.Unmarshal` directly.
- Fuzz tests run as part of `go test ./...` only with their
  seed corpus (the `f.Add(...)` calls). To actually mutate
  inputs, pass `-fuzz=<pattern>`:
  ```bash
  go test -fuzz=FuzzParseEntry -fuzztime=10s ./internal/lynis/...
  ```
- Failed inputs are saved to
  `internal/<package>/testdata/fuzz/<Target>/<hash>`. Re-run
  them with the standard test runner:
  ```bash
  go test -run=FuzzParseEntry/<hash> ./internal/lynis/...
  ```
- The trivy fuzz targets cap inputs at 1 MiB
  (`maxFuzzDecodeBytes`). The cap exists because the
  underlying `json.Unmarshal` can spend several seconds on
  deeply-nested adversarial input. The 1 MiB ceiling is well
  above any sane trivy report and keeps each iteration
  bounded. If a real-world report ever exceeds this, the
  cap should be raised, not removed.
- The `FuzzDecodeTrivyJSON` test does NOT assert that
  accepted input is also `json.Valid`. `json.Unmarshal` is
  more permissive than `json.Valid` (it tolerates trailing
  form feeds inside array literals), and the function
  deliberately mirrors `json.Unmarshal`. Don't tighten the
  assertion to require `json.Valid` — that would change the
  function's documented contract.

#### Property tests
- `internal/domain/scoring_props_test.go` runs `ScoreFindings`
  against 200 randomly-generated finding slices per test and
  asserts bounds, monotonicity, dedup, and clean-state
  invariants. The random number generator is seeded with a
  fixed PCG seed so the tests are deterministic.
- The score is bounded: `Overall` and every axis `Score` are
  in `[0, 100]`, every axis `Penalty` is in `[0, MaxPenalty]`.
  Regressions in the cap math or in the dedup key surface
  here.
- The `Snapshot` cache test
  (`TestScanProgress_Snapshot_ReflectsMutations`) asserts the
  cache invalidation contract: a snapshot taken before a
  mutation does not reflect the mutation. It does NOT
  assert that callers can safely mutate the returned
  snapshot's findings slice in place — the cached snapshot
  shares its backing array with the most recent returned
  value, and mutating the returned value would corrupt the
  cache. Callers must treat the returned value as read-only.

#### Benchmarks
- Benchmarks live in `internal/<pkg>/bench_test.go` next to
  the source. They cover the hot paths: `Snapshot`,
  `ScoreFindings`, `Recalculate`, `View`, and the cached
  `VisibleFindings` filter.
- Run every benchmark via the wrapper script:
  ```bash
  scripts/bench.sh                       # every benchmark, one iteration
  scripts/bench.sh -benchtime=3s         # 3 seconds per benchmark
  scripts/bench.sh -bench=Snapshot       # filter by name
  scripts/bench.sh -count=5              # 5 samples per benchmark
  ```
- Compare two runs with `benchstat` (install with
  `go install golang.org/x/perf/cmd/benchstat@latest`):
  ```bash
  scripts/bench.sh -benchtime=2s | tee before.txt
  # ... make your change ...
  scripts/bench.sh -benchtime=2s | tee after.txt
  benchstat before.txt after.txt
  ```
- The script runs with `-run=^$` so the regular test suite
  is excluded. Race detector is off (race inflates ns/op
  substantially).

## Debugging tips

- The TUI is a Bubble Tea v2 program. `tea.NewProgram(m).Run()`
  returns when the program exits. To debug the model state,
  add a `tea.Println(...)` call in `Update`, or use
  `lipgloss.Println` for styled output.
- The Web UI uses the standard `setInterval` poll, so you can
  attach DevTools to the running `hostveil serve` instance
  and inspect the DOM, the network panel, and the `state`
  global.
- `hostveil --no-scan` skips the scanner goroutines and just
  opens the UI, so you can iterate on layout without waiting
  for Trivy or Lynis.
- The Lynis report is written to a temp file and parsed in
  `internal/lynis/lynis.go`. To inspect what Lynis actually
  reported, the path is hardcoded. The easiest way is to
  add a `t.Logf` in the parser and run
  `go test ./internal/lynis/...` with a real `report.dat`.
- Scan history is at `/var/lib/hostveil/scans/`. Delete the
  directory to start clean. The directory is per-host, not
  per-user.

## Releasing

Releases are cut from the GitHub Actions release workflow on a
`v*` tag push. To cut a release:

```bash
git tag v2.5.3
git push origin v2.5.3
```

The workflow:

1. Runs `go build ./...` and `go vet ./...`.
2. Runs `goreleaser release --clean`, which:
   - Builds linux/darwin × amd64/arm64 binaries.
   - Embeds the version string with
     `-X internal/tui.Version={{.Version}}`.
   - Generates `hostveil-checksums.txt` and uploads all 4
     archives to the GitHub release.

After pushing a release tag, monitor the GitHub Actions run
at `https://github.com/seolcu/hostveil/actions`. The release
does not ship until the build and test jobs are green.
