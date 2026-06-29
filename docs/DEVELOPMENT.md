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
  `document.body`. They are styled with the same theme tokens
  as the main UI.

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
