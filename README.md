# hostveil

Linux self-hosting security scanner.

Scans your running Docker Compose projects and host system for security
misconfigurations, then lets you inspect the results in either a terminal UI
or an embedded Web UI.

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
- The TUI is optimized for quick local inspection. Findings are navigable
  with arrow keys; press Enter to view details and fix instructions.
- The Web UI is optimized for analysis: search, filter by severity/source/
  remediation, sort findings, inspect evidence, and copy guidance.
- On startup, `hostveil` checks GitHub for a newer release and notifies
  you. Use `--no-update` to disable.

## Features

- Single binary. Parallel scanning. Auto-detects running compose projects.
- Two UIs: a keyboard-driven TUI and a no-build embedded Web UI.
- Web analysis workflow: score cards, filters, search, sorting, detail panel,
  evidence viewer, and copyable remediation guidance.
- Graceful skip: if trivy or lynis is missing, scans that tool is skipped
  with a clear message—no crashes.
- Safe default Web bind address: `127.0.0.1:8787`.
- Port reclaim: if the requested Web UI port is already occupied, hostveil
  stops the existing listener process and takes the port.
- Fix engine (coming soon): apply fixes from the TUI with one key.

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
| `Esc` | Close detail view |
| `s` | Open theme selector |
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

Endpoints:

| Endpoint | Description |
|----------|-------------|
| `/` | Embedded Web UI |
| `/api/result` | JSON scan result |
| `/api/health` | Health check |

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

Verify changes:

```bash
go test ./...
go vet ./...
go build ./...
```

Tag a release:

```bash
git tag v2.0.1
git push origin v2.0.1
# GitHub Actions runs goreleaser automatically
```

Minimum Go version: 1.26.

## License

GPL-3.0
