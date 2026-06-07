# hostveil

Linux self-hosting security scanner.

Scans your running Docker Compose projects and host system for security
misconfigurations, then lets you inspect the results and apply fixes in
either a terminal UI or an embedded Web UI.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
hostveil
```

Prefer a browser-based workflow?

```bash
hostveil serve
```

Then open `http://127.0.0.1:8787`.

The installer prompts to install `trivy` and `lynis` automatically,
then downloads the `hostveil` binary to `/usr/bin`.

If a tool is not installed, `hostveil` skips it and shows how to install:
`run 'hostveil setup'` to open the installer again.

## Commands

| Command | Action |
|---------|--------|
| `hostveil` | Scan compose projects + host, open TUI |
| `hostveil serve` | Scan compose projects + host, serve Web UI on `127.0.0.1:8787` |
| `hostveil web` | Alias for `hostveil serve` |
| `hostveil serve --addr HOST:PORT` | Serve the Web UI on a custom address |
| `hostveil serve --fixture F` | Serve fixture data for E2E testing |
| `hostveil setup` | Install/update dependencies (trivy, lynis) |
| `hostveil update` | Upgrade hostveil to the latest release |
| `hostveil --no-update` | Skip the automatic update check on startup |
| `hostveil --version` | Show installed version |

## How it works

```
docker compose ls
  → Trivy: config + image scan
  → Lynis: host audit
  → merge + score
  → TUI or Web UI
```

- **Trivy** scans every running compose project for IaC misconfigurations
  (privileged containers, host network mode, sensitive mounts, etc.)
  and CVE vulnerabilities in service images.
- **Lynis** audits the host system for hardening gaps (SSH config,
  firewall status, kernel parameters, file permissions, etc.).
- Results are combined into a single score (0–100) and displayed in either
  the terminal UI or the embedded Web UI.
- **Fix engine**: press `f` to apply automated fixes for a finding directly
  from TUI, or click the Fix button in the Web UI for a dry-run preview first.
  Multi-action fixes offer a choice between options.
- On startup, `hostveil` checks GitHub for a newer release and notifies
  you. Use `--no-update` to disable.

## Features

- Single binary. Parallel scanning. Auto-detects running compose projects.
- Two UIs: a keyboard-driven TUI and a no-build embedded Web UI.
- Web analysis workflow: score cards, filters, search, sorting, detail panel,
  evidence viewer, and copyable remediation guidance.
- Interactive fix engine: apply config fixes, permission changes, sysctl
  settings, and image tag updates with one key.
- Graceful skip: if trivy or lynis is missing, scans that tool is skipped
  with a clear message—no crashes.
- Safe default Web bind address: `127.0.0.1:8787`.
- Port reclaim: if the requested Web UI port is already occupied, hostveil
  stops the existing listener process and takes the port.

## Requirements

- Linux (tested on Fedora, Ubuntu, Debian)
- Docker Engine 24+ (for compose project discovery)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Lynis](https://github.com/CISOfy/lynis)

Root access is required for host-level scanning. `hostveil` re-execs
via `sudo` automatically.

## TUI controls

| Key | Action |
|-----|--------|
| `j`/`↓`, `k`/`↑` | Navigate findings list |
| `Enter` | Open finding detail |
| `Esc` / `h` | Close detail view |
| `/` | Search findings |
| `f` | Apply fix (dry-run shown first) |
| `Space` | Select/deselect for batch fix |
| `Ctrl+A` | Select/deselect all visible |
| `0-4` | Filter by severity (0=all, 1=critical, ...) |
| `s` | Cycle source filter (all → trivy → lynis) |
| `r` | Cycle remediation filter |
| `o` | Cycle sort order |
| `O` | Toggle sort direction (asc/desc) |
| `v` | Cycle service filter |
| `R` (twice) | Clear all filters |
| `g` / `G` | Go to top / bottom |
| `Ctrl+R` | Recalculate score |
| `Ctrl+S` | Rescan all tools |
| `e` | Export report (JSON/CSV) |
| `?` | Toggle help |
| `q` | Quit |

## Web UI

```bash
hostveil serve
```

The Web UI is served from the same single binary. No Node.js, npm, or frontend
build step is required.

Default address:

```text
http://127.0.0.1:8787
```

Custom address:

```bash
hostveil serve --addr 127.0.0.1:9000
```

API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Embedded Web UI (app.js, app.css) |
| `/api/health` | GET | Health check — returns `{"status":"ok"}` |
| `/api/result` | GET | Full scan result as JSON (`domain.Snapshot`) |
| `/api/fix` | POST | Apply or preview (`info_only`) a fix for a finding |
| `/api/fix/batch` | POST | Apply fixes for multiple findings |
| `/api/rescan` | POST | Trigger full rescan (trivy + lynis) |
| `/api/recalc` | POST | Recalculate score without rescanning |
| `/api/export?format=json\|csv` | GET | Export findings as JSON or CSV download |

Security note: `hostveil` runs with root privileges for host scanning. The Web
UI binds to localhost by default. Binding to `0.0.0.0` exposes host scan results
to your network and should only be used in trusted environments.

## Development

```bash
git clone https://github.com/seolcu/hostveil
cd hostveil
go build -o hostveil ./cmd/hostveil/
./hostveil
# or
./hostveil serve
```

Before committing, run the full test suite:

```bash
gofmt -l .                          # format check
go build ./... && go vet ./...      # build + vet
go test ./...                       # Go unit + integration tests
cd test/e2e && npx playwright test  # E2E browser tests
cd ../.. && rm -f hostveil-e2e      # clean up
```

Tag a release:

```bash
git tag v2.3.0
git push origin v2.3.0
# GitHub Actions runs goreleaser automatically
```

After pushing, monitor CI/CD results at `https://github.com/seolcu/hostveil/actions`.

Minimum Go version: 1.26.

## License

GPL-3.0
