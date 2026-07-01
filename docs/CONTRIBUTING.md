# Contributing

Thanks for considering a contribution. This project has a small
surface area and a high bar for changes that touch scoring, the
fix engine, or the Web UI. Before opening a pull request, please
read:

1. `AGENTS.md`, the in-repo agent guide with the actual
   conventions the codebase uses.
2. `docs/ARCHITECTURE.md`, the package layout and data flow.
3. `docs/DEVELOPMENT.md`, the local workflow and test layout.

## How to contribute

### Bug reports

Open a GitHub issue with:

- The exact hostveil version (`hostveil --version`).
- The host OS and architecture.
- The exact command that produced the bug.
- The expected output and the actual output.
- For UI bugs, a screenshot or screencast.

### Code changes

1. Fork the repo and create a topic branch.
2. Make your change. Follow the conventions in `AGENTS.md` and
   `docs/DEVELOPMENT.md`.
3. Add tests. The change should fail without your fix and pass
   with it.
4. Run the full local verification:

   ```bash
   gofmt -l .
   go build ./...
   go vet ./...
   go test -race ./...
   cd test/e2e && npx playwright test
   ```

5. Push your branch and open a pull request. The CI runs the
   same checks plus a `test-installer` matrix across six
   distros. All jobs must be green before the PR can be merged.

### New fix rules

The most common kind of contribution is a new fix for an
existing finding ID. To add one:

1. Find the finding ID. It is the `id` field in the Web UI or
   the `lynis.XXXX-YYYY` / `trivy.cve-YYYY-NNNNN` /
   `compose.XXXX` pattern in the JSON.
2. Pick the right remediation kind (`Auto`, `Review`,
   `Manual`). Read
   `AGENTS.md#fix-engine-critical--internalfix` first.
3. Implement the fix in the right file:
   - `internal/fix/compose.go` for compose misconfigurations
   - `internal/fix/system.go` for host hardening
   - `internal/fix/images.go` for CVE image fixes
4. Add a test in the corresponding `_test.go`.
5. If the finding ID is from a scanner (Lynis, Trivy), make sure
   the ID is one that the scanner actually emits. The
   `TestLynis316_RegisteredIDsAreValid` test enforces this for
   Lynis.

### New scanner backends

A new scanner backend is a 200-400 LoC change spread across
three files:

- `internal/<name>/<name>.go`, the scanner adapter, exposing a
  single `Scan(runner domain.CommandRunner) ([]domain.Finding, error)`
  function.
- `internal/scan/scan.go`, add the tool name to the dispatch
  switch in `RunSingleTool`.
- `cmd/hostveil/scanhelp.go`, add the launch goroutine in
  `launchScanners`.

Add a test fixture and a Playwright spec that exercises the new
finding kind in both the TUI and the Web UI.

### Documentation

- User-facing documentation lives in `README.md` and
  `docs/ARCHITECTURE.md`. The README is the entry point.
  Keep it in sync with the actual behavior of the binary.
- Contributor-facing documentation lives in `AGENTS.md`,
  `docs/DEVELOPMENT.md`, and `docs/CONTRIBUTING.md` (this
  file).
- API documentation is the GoDoc comments on every exported
  symbol. Run `go doc ./...` to spot-check.

## Coding style

The codebase follows standard Go style:

- `gofmt` and `go vet` must pass without warnings.
- Comments on every exported symbol. Comments start with the
  symbol name. "Package foo does X." not "This package does X."
- No `init()` outside of `package main`.
- Errors are wrapped with `%w`, never `%v`.
- No exported mutable package-level state. Use a `New()`
  constructor that returns a pointer.

## Commit messages

Single line, imperative mood, 50 chars or less. Examples:

```
fix: bound-check action_index in /api/fix
feat: add KRNL-5820 core-dump fix
docs: explain the 4-axis scoring model
```

A scope tag (`fix:`, `feat:`, `docs:`, `test:`, `chore:`) is
encouraged but not enforced.

## Review process

Pull requests are reviewed by the maintainers. The typical
turnaround is 2-5 days. Reviews focus on:

- Does the change match the design rules in `AGENTS.md`?
- Is the test coverage adequate? (Both unit and E2E for UI
  changes.)
- Does the change break any existing behavior? (Scoring
  changes are the riskiest. Bumping a penalty or changing a
  cap is a user-visible behavior change.)
- Are there documentation updates needed?

## Code of conduct

Be kind. Disagree on technical merit, not on the contributor.
Harassment of any kind is not tolerated.
