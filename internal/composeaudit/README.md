# composeaudit

Native Docker Compose audit. Reads the compose YAML, applies a
set of rules, and emits `domain.Finding` values. hostveil runs
this in-process  no Trivy, no shell out, no extra tool needed.

## Files

- **`audit.go`**  `ScanAll`, the per-project scanner entry point.
- **`discover.go`**  `DiscoverProjects` shells out to
  `docker compose ls --format json` to find the active compose
  projects and their config paths.
- **`env.go`**  `.env` file parsing for compose variable
  resolution (so a `port: ${WEB_PORT:-8080}` doesn't trip the
  "exposing to all interfaces" rule).
- **`rules.go`**  the audit rules. One function per rule.
- **`audit_test.go`**  `TestAuditProject_*` for each rule.

## Rules

| ID | Severity | Concern |
|----|----------|---------|
| `compose.DR-001` | High | `privileged: true` |
| `compose.DR-002` | High | `network_mode: host` |
| `compose.DR-003` | High | `pid_mode: host` |
| `compose.DR-004` | High | Hardcoded secret in compose file |
| `compose.DR-005` | High | `ipc_mode: host` |
| `compose.DR-006` | High | `userns_mode: host` |
| `compose.DR-007` | High | `cap_add` includes a dangerous capability |
| `compose.DR-008` | Medium | `security_opt` missing `no-new-privileges` |
| `compose.DR-009` | High | Container runs as root (`user: root` or no `user` field) |
| `compose.DR-010` | Medium | `restart: always` (against Docker best practice for stateful services) |
| `compose.DR-011` | Medium | No memory limit |
| `compose.DR-012` | Medium | No CPU limit |
| `compose.DR-013` | Medium | No `healthcheck` defined |
| `compose.DR-014` | Medium | Port bound to `0.0.0.0` or unspecified |
| `compose.DR-015` | Medium | Sensitive host directory mounted |
| `compose.DR-016` | High | `seccomp` profile is `unconfined` |
| `compose.DR-017` | High | `apparmor` profile is `unconfined` |
| `compose.DR-018` | Medium | Bind mount not read-only when it could be |
| `compose.DR-019` | High | Secret present in `.env` file |

(Not all rule IDs are in this list  see `rules.go` for the
complete set. The list is illustrative.)

## Variable resolution

Compose files can use `${VAR}` or `${VAR:-default}` syntax.
`env.go` parses `.env` files (and the host environment, scoped
to the variable names referenced) so that rules can see the
resolved values. A `port: ${WEB_PORT:-8080}` with a default of
`8080` is treated as `8080`, not as a literal `${WEB_PORT:-8080}`.

## Public API

```go
// Discover the running compose projects and audit each one.
// Returns the merged findings and an optional error from the
// "docker compose ls" call.
func ScanAll(runner domain.CommandRunner) ([]domain.Finding, error)
```

## Tests

```bash
go test ./internal/composeaudit/...
```

`audit_test.go` runs every rule against a fixture compose file
and asserts the expected `domain.Finding` for each.
