<!--
Title: conventional and with a scope from the allowlist — e.g. `fix(check): ...`,
`feat(ui): ...`. The title becomes the squashed commit subject and drives the
version bump and changelog, so put the component in the SCOPE, never the type.
See AGENTS.md for the allowlist and the reasoning. CI enforces it.
-->

## What and why

<!-- What does this change do, and what problem does it solve? Link any issue: Closes #123 -->

## Checklist

- [ ] Title is conventional with a valid scope (`type(scope): ...`).
- [ ] Ran the CI gate locally and it passes:
  ```
  go build ./... && go vet ./... && gofmt -l . && go mod tidy && go test -race ./...
  golangci-lint run ./...
  go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
  go run ./cmd/sitegen && git diff --exit-code site/
  ```
  `golangci-lint` must be the v2.12.2 **release binary**. `go run …@v2.12.2`
  is built against an older toolchain than this module targets and refuses
  before it reads the config, so it lints nothing and looks like it passed.
- [ ] For a new or changed detection rule: added the case that must **not** trigger it, not just the one that must.
- [ ] For a UI change: included a screenshot, or confirmed the TUI/web layering tests still pass.
- [ ] The score stays honest — a checker that can't look reports skipped/degraded, it never passes "couldn't look" off as "nothing there" (see AGENTS.md invariants).
