# composeaudit

Native Docker Compose audit. Reads the compose YAML, applies a
set of rules, and emits `domain.Finding` values. hostveil runs
this in-process  no Trivy, no shell out, no extra tool needed.

## Files

- **`audit.go`** — `ScanAll`, the per-project scanner entry point.
- **`discover.go`** — `DiscoverProjects` shells out to
  `docker compose ls --format json` to find the active compose
  projects and their config paths.
- **`env.go`** — `detectEnvFiles` flags services whose `env_file`
  points at a non-empty file (`compose.dr004`). It does not parse
  the file contents.
- **`rules.go`** — the audit rules. One function per rule.
- **`audit_test.go`** — `TestAuditProject_*` for each rule.

## Rules

All IDs are lowercase. The `ds`/`dr` prefix split roughly separates
per-service checks from checks that also touch cross-cutting
resources (ports, volumes, `.env` files) or run once per compose
file, but the boundary is historical, not a strict rule — check
`rules.go` for what a given ID actually does. This table should be
kept in sync with `rules.go`; if you add a rule, add its row here.

| ID | Severity | Concern |
|----|----------|---------|
| `compose.ds001` | High | `privileged: true` |
| `compose.ds002` | Medium | `read_only` not set (writable root filesystem) |
| `compose.ds003` | Medium | `pid: host` |
| `compose.ds004` | Medium | `ipc: host` |
| `compose.ds005` | High | `cap_add` includes a dangerous capability (`SYS_ADMIN`, `NET_ADMIN`, `SYS_RAWIO`, `SYS_PTRACE`, `SYS_MODULE`) |
| `compose.ds006` | Medium | `security_opt` missing `no-new-privileges:true` |
| `compose.ds007` | Medium | `userns_mode: host` |
| `compose.ds008` | Low | `restart` unset or `no` |
| `compose.ds009` | Medium | Container runs as root (`user` unset, `root`, or UID `0`) |
| `compose.ds010` | Low | No memory limit |
| `compose.ds011` | Low | No CPU limit |
| `compose.ds012` | Low | No `healthcheck` defined |
| `compose.ds013` | Low | `tmpfs` mount missing `noexec` |
| `compose.ds014` | Medium | `security_opt` has `seccomp:unconfined` |
| `compose.ds015` | Medium | `security_opt` has `apparmor:unconfined` |
| `compose.ds016` | Critical | Docker socket (`/var/run/docker.sock` or `/run/docker.sock`) bind-mounted into the container — equivalent to root on the host, `:ro` does not mitigate it |
| `compose.ds017` | High | Sensitive host root (`/`, `/etc`, `/root`, `/home`, `/boot`, `/proc`, `/sys`, `/run`, `/var/run`, or a `.ssh` directory) mounted read-write |
| `compose.dr001` | High | `network_mode: host` or `network_mode: container:<other>` |
| `compose.dr002` | Medium | Port bound to `0.0.0.0` (short or long syntax) |
| `compose.dr003` | Low | Volume mounted without `:ro` when it could be read-only |
| `compose.dr004` | High | `env_file` referencing a non-empty file (scored under the Secrets axis, not Container exposure) |

`compose.ds016` and `compose.ds017` both parse only Compose
short-syntax volume entries (`SOURCE:TARGET[:MODE]`); long-syntax
mapping-form volumes (`type: bind`, `source:`, `target:`) are not
yet inspected by these two rules (`compose.dr002`'s long-syntax
port form *is* handled — see `checkPortBinding`).

## Known limitation: no `${VAR}` interpolation

Compose supports `${VAR}` / `${VAR:-default}` substitution in any
field. `rules.go` reads raw YAML scalars via
`compose.File.GetFieldStrings` — it does not resolve these
variables. A port mapping like `"${WEB_PORT:-8080}:8080"` will not
be recognized as exposing 8080 on all interfaces, because the
colon inside `:-8080` is not the mapping separator the port-parsing
heuristic expects. Prefer literal values in compose files you want
audited precisely, or resolve with `docker compose config` before
reasoning about exposure by hand.

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
