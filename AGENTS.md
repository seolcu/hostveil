# AGENTS.md: hostveil

> For coding agents. If you are a human contributor, start with
> [`README.md`](README.md) and [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).
> This file is the agent-focused contract for working on the codebase.

hostveil is a single-binary Linux security scanner. It runs a native
Docker Compose audit plus Trivy (CVE + IaC) and Lynis (host
hardening) backends, and renders findings in either a Bubble Tea
TUI or an embedded Web UI. The codebase is small (~13.5k LoC Go)
but the fix engine, the scoring model, and the Web UI's XSS
surface have design rules that are easy to break. Read this file
before you touch anything.

### Tech stack

- **Language:** Go 1.26, module `github.com/seolcu/hostveil`
- **TUI:** `charm.land/bubbletea/v2`, `charm.land/bubbles/v2`,
  `charm.land/lipgloss/v2`. Do not downgrade to v1.
- **YAML AST:** `gopkg.in/yaml.v3`
- **Frontend:** hand-rolled ES2020+ in `internal/web/assets/app.js`.
  No build step.
- **External runtime deps:** `docker` (compose discovery), `trivy`
  (CVE + IaC), `lynis` (host hardening). Missing tools are skipped,
  not fatal.
- **E2E tests:** Playwright on Node 20+ (only for the Web UI).

## Workflow

Every change follows this loop:

1. **Read the relevant doc** from the index below.
2. **Plan the change**. List the files, the tests, and which design
   rules apply.
3. **Edit**. Keep changes tight. Follow the conventions in this file
   and the per-package READMEs.
4. **Verify locally**. The four checks below must pass before you
   claim the change works.
5. **Verify CI**. After push, watch `build`, `test-installer`, and
   `e2e`. Do not declare done until all three are green.
6. **Clean up** using the Cleanup checklist below.

If you are blocked or unsure, say so. Do not guess at intent. A
short "I need X, here is why" beats a plausible but wrong fix.

## Documentation index

Read in order. Skip only the sections that are not relevant to your
change. Never skip the one that is.

| Doc | When to read |
|-----|--------------|
| [`README.md`](README.md) | First time. What hostveil is, who uses it, install steps. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Before touching `internal/domain`, `internal/scan`, `internal/fix`, the Web UI, or the TUI. Covers the scoring model, the data flow, and the concurrency model. |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Before your first build, before your first test run, before opening a PR. Local workflow, test layout, conventions. |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Before opening a PR. The PR template, the review checklist, how to add a new fix rule. |
| [`SECURITY.md`](SECURITY.md) | Before touching the Web UI, the fix engine, the port reclaim, or anything that writes to the host filesystem. Threat model, what hostveil protects against, how to report. |
| [`CHANGELOG.md`](CHANGELOG.md) | Before writing release notes. Past entries, breaking changes, security fixes. |
| `internal/*/README.md` | Before editing that package. Per-package public API, file layout, tests. |

## Build and test

The four local checks. **All four must pass before you claim the
change works.** Run them in this order. `gofmt` is fastest, e2e is
slowest, so fail fast.

```bash
# 1. Format
gofmt -l .                      # must print nothing

# 2. Build + vet
go build ./...
go vet ./...

# 3. Go tests (race detector)
go test -race ./...

# 4. E2E (Playwright; requires Node.js 20+)
go build -o hostveil-e2e ./cmd/hostveil/
( cd test/e2e && npm ci && npx playwright install chromium )
( cd test/e2e && npx playwright test )
rm -f hostveil-e2e test/e2e/.e2e-server-pid test/e2e/.e2e-kill.sh
rm -rf test/e2e/test-results test/e2e/playwright-report
```

Targeted runs for faster feedback while iterating:

```bash
go test -race ./internal/fix/...                       # one package
go test -race ./internal/fix/... -run "TestKRNL"       # one prefix
go test -race ./internal/web/... -run "TestHandleFix"  # one set
( cd test/e2e && npx playwright test specs/dashboard.spec.ts )   # one spec
( cd test/e2e && npx playwright test --grep "Score" )            # one grep
```

The installer matrix is run by CI only. Do not run it locally
unless asked. The `hostveil-e2e` binary and `test/e2e/test-results/`
are build artefacts. They are gitignored. Do not commit them.

## Repository layout

Single Go module (`github.com/seolcu/hostveil`). No Makefile, no
codegen, no frontend build chain.

```
cmd/hostveil/         main package, subcommands, signal handling
internal/
  domain/             types, scoring, scan progress
  scan/               single-tool dispatcher
  trivy/              Trivy adapter (config and image)
  lynis/              Lynis adapter (host hardening)
  composeaudit/       native Docker Compose audit
  compose/            YAML AST editing primitives
  fix/                fix registry: compose, system, image
  history/            checkpoints and scan history on disk
  tui/                Bubble Tea v2 UI
  web/                embedded HTTP server and static Web UI
test/
  e2e/                Playwright specs
```

Each `internal/*` has its own README. Read it before editing.

## Code conventions

These are the conventions the codebase actually uses. If you are
adding code, follow them. If you are editing code that violates
them, fix the violation as part of your change.

### Go

- `gofmt` formatting. No exceptions.
- Comments on every exported symbol. Start with the symbol name.
  "Package foo does X." not "This package does X."
- Errors are wrapped with `fmt.Errorf("context: %w", err)`. Never
  `%v` for an error chain.
- No `panic` outside of `init`. No ignored errors with `_ =` unless
  a comment explains why the ignore is safe.
- `sync.RWMutex` for any field shared between the TUI/Web UI and
  the scanner goroutines. The canonical example is
  `domain.ScanProgress`.
- Bubble Tea v2 value-receiver `Update`. Anything you need to
  mutate from a background goroutine goes through `m.send(msg)`,
  not by mutating a captured model.
- Cross-platform shell scripts use `command -v` (not `which`).
- Tests use `t.TempDir()` for any FS work and `httptest.NewServer`
  for HTTP. Do not start a real listener in tests.

What good code looks like:

```go
// Good: comment starts with symbol name, wraps with %w, no panic
func Open(path string) (*File, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("read %s: %w", path, err)
    }
    return &File{path: path, doc: doc}, nil
}

// Bad: comment starts with "This", error is discarded, panics
func Open(path string) *File {
    data, _ := os.ReadFile(path)  // ignore errors
    if data == nil {
        panic("file is empty")    // no panic outside init
    }
    return nil
}
```

### Web UI

- No build step. Plain ES2020+ in `internal/web/assets/app.js`.
  Hand-rolled template strings, no JSX, no bundler.
- Every value rendered into `innerHTML` must be HTML-escaped. The
  shared helper is `escapeHTML(...)`. Browser-decoded `data-*`
  attribute values must be re-escaped on read, since the browser
  has already done entity-decoding once. `app.js:section()` and
  the "View more" / "View less" toggle are the historical hot
  spots. `test/e2e/specs/xss.spec.ts` covers them.
- Modal overlays are `position: fixed` divs appended to
  `document.body`.
- Server defaults: `127.0.0.1:8787`. Bind to `0.0.0.0` only on
  explicit request. A one-line warning is emitted to stderr.

### Fix engine (high-risk area)

The fix engine is the part of the codebase most likely to break in
a way that goes unnoticed. These rules are enforced by tests, not
just convention. Read [`internal/fix/README.md`](internal/fix/README.md)
and the design rules below before touching `internal/fix/`.

**1. `Review` = alternatives, NOT stages.**

A `Review` fix represents independent alternative solutions the
user picks between. The user picks ONE of N options, or any
subset. Each action must address the concern independently. None
of them depend on the others being applied.

Counter-example (the KRNL-6000 mistake). Originally registered as
1 bundled action that applied 6 sysctls together. Wrong: it forced
the user to accept all 6 or none. A user running a router may want
`syncookies=1` but NOT `accept_source_route=0`. Reverted to 6
separate actions so the user can pick any subset.

Positive example: SSH-7408. 5 independent actions (Compression,
MaxAuthTries, TCPKeepAlive, AllowAgentForwarding, MaxSessions).
Each is an independent sshd directive. User picks any subset.

**2. A single-action fix is `Auto`, not `Review`.**

A single-action fix labeled `Kind: RemediationReview` is misleading.
The user has no choice. Use `Kind: RemediationAuto` and put the
concern in the action's `Warning` field. The UI shows a warning
dialog before applying.

**3. A fix reporting `success=true` must have made the change.**

Common silent-failure patterns to avoid:

- Shell scripts ending in `exit 0` (the `exit 0` masks earlier
  failures from `set +e` or `||` chains. v2.5.0 had this bug in
  LOGG-2130, ACCT-9628, TIME-3104 install scripts.)
- `set +e` for the whole script (conflates install failures with
  start failures).
- A Go `Apply` function that ignores `err`.

Correct pattern: `set -e` for required steps, `|| true` for
best-effort service start in containers without an init system.
This is enforced by `TestRunInstallAndStart_PackageFailurePropagates`
in `internal/fix/system_actions_test.go`.

**4. Every multi-action fix needs exhaustive tests for each action
index, not just action 0.**

Use path-parameterized core helpers (`sshdSetOptionAt`,
`loginDefsSetAt`, `fileAppendIfMissingAt`) so tests can run
against `t.TempDir()` files. See `internal/fix/system_actions_test.go`
for the canonical pattern.

**5. Wildcard registration (`trivy.cve-*` etc.) is for variable
IDs only.**

Prefer exact IDs for everything else, so `HasExactEntry` can
correctly drive the related-finding cascade. Wildcard fixes never
auto-mark related findings as fixed.

## Boundaries

Three tiers. Items at the same tier are equally important.

### Always do

- `gofmt -l .` and the four local checks pass before pushing.
- Lynis findings use stable test IDs (`AUTH-9286`) in the finding
  ID: `"lynis.AUTH-9286"`. The `lynis.` prefix is the
  registration key for `fix.Registry`.
- `internal/fix` rule additions come with a test that fails
  before the fix and passes after.
- Cross-platform shell scripts use `command -v` (not `which`).
- The AGENTS.md, README.md, and per-package READMEs are kept in
  sync with the code. When you change a command, a public API,
  or a workflow, update the corresponding doc in the same commit.
  Stale instructions are worse than missing instructions.

### Ask first

- Adding a new dependency. Dependencies are a long-term maintenance
  commitment, not a one-line change.
- Adding a new public symbol to the Web UI or the TUI. This
  changes the user-visible surface and the maintainer will want
  to review the UX decision.
- Changing the scoring model. Score changes are user-visible
  behavior changes. Re-read `docs/ARCHITECTURE.md` first.
- Touching `/var/lib/hostveil/` schema or paths (history,
  checkpoints, scan records). Backwards compatibility with
  existing users' data matters.
- Releasing. Releases are cut from GitHub Actions on a `v*` tag
  push. Do not run goreleaser locally.

### Never do

- Commit secrets, API keys, tokens, or anything that resembles a
  credential. GitHub token is injected via
  `${{ secrets.GITHUB_TOKEN }}`. Never hardcode it.
- Add `sudo` inside `internal/trivy` or `internal/lynis`. The
  process is already root when they run.
- Change `ensureSudo()` to use `sudo -v` or a child-process
  wrapper. The re-exec via `sudo os.Args...` with
  `cmd.Env = os.Environ()` is intentional.
- Downgrade Bubble Tea from v2 to v1. Use `tea.KeyPressMsg` and
  `tea.View`, not the v1 `charmbracelet/...` paths.
- Inject any value into `innerHTML` without `escapeHTML(...)`.
  Browser-decoded `data-*` attribute values must be re-escaped
  on read. See "Security" below.
- Revert a fix that reverts to `set +e; exit 0` or removes a
  `set -e`. Fix scripts must fail loudly on error.
- Change `.gitignore` `/hostveil` (prefixed slash) to `hostveil`.
  That would also ignore `cmd/hostveil/`.
- Silently change the port reclaim logic. The current behavior
  (only reclaim from `hostveil` processes) is intentional.

### Files and paths to leave alone

These exist for a reason. Touching them is almost always wrong:

- `internal/web/assets/`. Embedded at build time. Changes here
  are picked up by the next build, but the served bundle lives in
  the binary.
- `/var/lib/hostveil/scans/` and `/var/lib/hostveil/checkpoints/`.
  Runtime data, not source. Don't add source code here.
- `cmd/hostveil/util.go`. `hasFlag` and `localIP` are stable.
  Don't move them.
- `go.mod` / `go.sum`. Only bump with a clear reason in the PR
  body. Auto-bumps from `go mod tidy` on every commit are noise.

## Security

Read [`SECURITY.md`](SECURITY.md) before touching any of:

- The Web UI server (`internal/web`).
- The fix engine (`internal/fix`), specifically anything that runs
  `Apply` on user-controlled input.
- The port reclaim logic.
- Anything that writes under `/var/lib/hostveil/`.

The two non-obvious traps:

- **XSS via `data-*` attribute decoding.** Browser
  `Element.dataset.foo` auto-decodes HTML entities in `data-foo`
  attribute values. A description containing `<script>` from a
  malicious scan source (Trivy, Lynis, compose YAML) will execute
  if you inject the dataset value back into `innerHTML` without
  re-escaping. The canonical fix: `escapeHTML(body.dataset.foo)`.
  The regression test is `test/e2e/specs/xss.spec.ts`.
- **Out-of-range `action_index` in `/api/fix`.** The handler
  dereferences `f.Actions[req.ActionIndex].Label` for the
  checkpoint metadata before bounds-checking. A negative index,
  an index beyond the slice length, or a fix with zero actions
  will panic the process. The handler now bounds-checks up front
  and returns a clear error. Regression test:
  `TestHandleFix_OutOfRangeActionIndex` in
  `internal/web/server_test.go`.

## Adding a fix rule

1. Read [`internal/fix/README.md`](internal/fix/README.md) and the
   design rules above.
2. Pick the right file:
   - `internal/fix/compose.go` for compose misconfigurations
   - `internal/fix/system.go` for host hardening (Lynis)
   - `internal/fix/images.go` for CVE image fixes
3. `r.Register(&Fix{...})` with the right `Kind` and actions.
4. Add a test. The test must fail before your fix and pass after.
5. For Lynis IDs, `TestLynis316_RegisteredIDsAreValid` enforces
   that every registered fix ID is one the parser actually emits.
6. For multi-action fixes, follow the pattern in
   `internal/fix/system_actions_test.go`: parametrized tests for
   every action index.

## Commit and PR

- Commit message format: `area: imperative description`. `area` is
  one of `fix`, `feat`, `docs`, `test`, `refactor`, `chore`. 50
  chars or less. Examples:
  - `fix: bound-check action_index in /api/fix`
  - `feat: add lynis.KRNL-5820 core-dump fix`
  - `docs: explain the 4-axis scoring model`
- PR title matches the commit message style.
- PR body describes why the change is needed. The diff shows
  what changed. Do not restate the diff in prose.
- Tests must fail before your fix and pass after. No
  "harmless refactor" PRs that are not actually testable.
- Run the four local checks before pushing. If CI fails after
  push, fix and re-push immediately.
- Watch CI until all jobs are green. Use `gh run watch` or the
  Actions API. Do not declare done until `build`, `test-installer`,
  and `e2e` are all green.
- One PR per concern. If you find an unrelated bug while working,
  file it as a separate issue or PR.

## Cleanup

Before yielding the change:

- [ ] `gofmt -l .` is silent.
- [ ] `go test -race ./...` passes.
- [ ] `cd test/e2e && npx playwright test` passes.
- [ ] No `hostveil-e2e` binary, `.e2e-server-pid`, `.e2e-kill.sh`,
      `test-results/`, or `playwright-report/` left behind.
- [ ] No debug `fmt.Println` or `log.Println` left in changed code.
- [ ] No commented-out code blocks. Delete them. Git remembers.
- [ ] No new `TODO`, `FIXME`, or `XXX` in changed code. If the work
      is incomplete, finish it or leave it for a follow-up PR with
      a tracking issue.
- [ ] Per-package README updated if you changed the public API.
- [ ] `CHANGELOG.md` updated under the `[Unreleased]` section if
      the change is user-visible.
- [ ] If you changed a build/test command, a public flag, or a
      workflow, this file (`AGENTS.md`) and any touched per-package
      `README.md` reflect the new behavior. Stale docs are a bug.
- [ ] No unrelated changes. Re-read the diff with `git diff
      main...HEAD` and remove anything that is not the task.

## When you are stuck

- The change is unclear. Ask the user. Do not guess at intent.
- The change breaks an existing test. Fix the change, not the
  test. Existing tests are part of the spec.
- A new dependency is required. Ask the user. Adding a dependency
  is a maintenance commitment, not a one-line change.
- The fix touches scoring. Re-read `docs/ARCHITECTURE.md` and
  the "Score is a weighted sum across four axes" section. Score
  changes are user-visible behavior changes. Treat them as such.
- The fix touches the Web UI XSS surface. Re-read the Security
  section above. The regression test in
  `test/e2e/specs/xss.spec.ts` is the safety net.

## Sources

This file is modeled on the patterns the broader community has
converged on for AGENTS.md. The four most influential sources:

- [The AGENTS.md spec](https://agents.md/): the canonical format
  and the list of supporting agents.
- [GitHub blog: "How to write a great agents.md: Lessons from
  over 2,500 repositories"](https://github.blog/ai-and-ml/github-copilot/how-to-write-a-great-agents-md-lessons-from-over-2500-repositories/):
  the six core areas (commands, testing, project structure, code
  style, git workflow, boundaries), the three-tier boundary
  pattern, and the "code examples over explanations" rule.
- [The Prompt Shelf: "AGENTS.md Best Practices"](https://thepromptshelf.dev/blog/agents-md-best-practices/):
  the "Don't define agents you never use" and "Don't skip
  project context" anti-patterns.
- [Agent Ready: "How to write an effective AGENTS.md"](https://agent-ready.dev/how-to-write-an-effective-agents-md):
  the "Don't touch" section, the 50-200 line target, and the
  "stale commands" pitfall.
