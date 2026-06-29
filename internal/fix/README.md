# fix

The fix registry: turns finding IDs into one or more concrete fix
actions the user can apply.

## Files

- **`types.go`** — `Action`, `Fix`, `FixResult`, `Context`,
  `Registry`, and the dispatch logic (`Fix.Run`, `Registry.Classify`).
  This is the vocabulary the rest of `internal/fix` builds on.
- **`register.go`** — `RegisterAll` wires up the three groups of
  fixes: compose, system, image.
- **`compose.go`** — fixes for Docker Compose misconfigurations
  (privileged, caps, mounts, ports, healthchecks, secrets, etc).
  Each fix uses `ActionEdit` against the compose YAML via
  `internal/compose`.
- **`system.go`** — fixes for Lynis host-hardening findings
  (SSH, kernel sysctls, file perms, banners, audit, logging, ...).
  Uses `ActionEdit` for config files, `ActionExec` for shell
  commands.
- **`images.go`** — fixes for Trivy CVE findings. Pulls the patched
  image and recreates the affected service. Skipped when no
  `FixedVersion` is available.
- **`edit.go`** — `SimulateDiff` (dry-run) and `CaptureDiff` (real
  apply), used by `ActionEdit` to produce a unified diff for the UI.
- **`types_test.go`** — registry and dispatch tests.
- **`compose_test.go`**, **`system_test.go`**, **`images_test.go`** —
  per-source tests.
- **`system_actions_test.go`** — exhaustive tests for every action
  of every multi-action fix.
- **`system_validate_test.go`** — asserts that every registered
  fix ID is one that Lynis actually emits.

## Conventions

These conventions are enforced by the existing tests. If you are
adding a fix and the test fails, the test is telling you that the
convention is more important than your fix.

### `Auto` vs `Review`

- **`Auto`** — one clear solution. Single action, no input needed.
  Use `Action.Warning` to flag side effects; the UI shows a warning
  dialog.
- **`Review`** — multiple valid options. The user picks one. Each
  action must address the concern **independently** of the others;
  the user can apply any subset. Never bundle N settings into one
  action.

### Success must reflect actual change

A fix reporting `success=true` MUST have made the change. Tests
verify this:

- `TestRunInstallAndStart_PackageFailurePropagates` in
  `system_actions_test.go` ensures that a failed package install
  propagates as a fix error.

Shell scripts inside `Action.Apply` functions use `set -e`. The
last service-start step is allowed to fail (`|| true`) in
environments without an init system.

### Wildcard registration

`Registry.Register` accepts `*` and `?` as wildcards in the
finding ID. Use wildcards only for findings whose ID is genuinely
variable (e.g. `trivy.cve-*`); prefer exact IDs for everything
else, so `HasExactEntry` can correctly drive the related-finding
cascade.

## Adding a fix

1. Read `AGENTS.md#remediationkind-classification-rules`.
2. Pick the right file (`compose.go`, `system.go`, or `images.go`).
3. Register the fix with `r.Register(&Fix{...})`.
4. Add a test in the corresponding `_test.go`. The test should
   fail before your fix and pass after.
5. If the fix is for a Lynis ID, the `system_validate_test.go`
   check will keep your ID in sync with the Lynis report parser.
6. For multi-action fixes, follow the pattern in
   `system_actions_test.go`: parameterized tests for every action
   index, not just action 0.

## Running the tests

```bash
go test ./internal/fix/...
go test -race ./internal/fix/...
```
